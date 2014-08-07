/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/private_config.h"

#include <stdio.h>
#include <sys/types.h>

#include "cci.h"
#include "cci_lib_types.h"
#include "cci-api.h"
#include "plugins/ctp/ctp.h"
#include "ctp_e2e.h"

e2e_globals_t *eglobals = NULL;

/*
 * Local functions
 */
static int ctp_e2e_init(cci_plugin_ctp_t * plugin, uint32_t abi_ver, uint32_t flags, uint32_t * caps);
static int ctp_e2e_finalize(cci_plugin_ctp_t * plugin);
static const char *ctp_e2e_strerror(cci_endpoint_t * endpoint, enum cci_status status);
static int ctp_e2e_create_endpoint(cci_device_t * device,
				    int flags,
				    cci_endpoint_t ** endpointp,
				    cci_os_handle_t * fd);
static int ctp_e2e_destroy_endpoint(cci_endpoint_t * endpoint);
static int ctp_e2e_accept(cci_event_t *event, const void *context);
static int ctp_e2e_reject(cci_event_t *event);
static int ctp_e2e_connect(cci_endpoint_t * endpoint, const char *server_uri,
			    const void *data_ptr, uint32_t data_len,
			    cci_conn_attribute_t attribute,
			    const void *context, int flags, const struct timeval *timeout);
static int ctp_e2e_disconnect(cci_connection_t * connection);
static int ctp_e2e_set_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, const void *val);
static int ctp_e2e_get_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, void *val);
static int ctp_e2e_arm_os_handle(cci_endpoint_t * endpoint, int flags);
static int ctp_e2e_get_event(cci_endpoint_t * endpoint,
			      cci_event_t ** event);
static int ctp_e2e_return_event(cci_event_t * event);
static int ctp_e2e_send(cci_connection_t * connection,
			 const void *msg_ptr, uint32_t msg_len,
			 const void *context, int flags);
static int ctp_e2e_sendv(cci_connection_t * connection,
			  const struct iovec *data, uint32_t iovcnt,
			  const void *context, int flags);
static int ctp_e2e_rma_register(cci_endpoint_t * endpoint,
				 void *start, uint64_t length,
				 int flags, cci_rma_handle_t ** rma_handle);
static int ctp_e2e_rma_deregister(cci_endpoint_t * endpoint, cci_rma_handle_t * rma_handle);
static int ctp_e2e_rma(cci_connection_t * connection,
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
cci_plugin_ctp_t cci_ctp_e2e_plugin = {
	{
	 /* Logistics */
	 CCI_ABI_VERSION,
	 CCI_CTP_API_VERSION,
	 "e2e",
	 CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
	 1, /* priority set to 1 */

	 /* Bootstrap function pointers */
	 cci_ctp_e2e_post_load,
	 cci_ctp_e2e_pre_unload,
	 },

	/* API function pointers */
	ctp_e2e_init,
	ctp_e2e_finalize,
	ctp_e2e_strerror,
	ctp_e2e_create_endpoint,
	ctp_e2e_destroy_endpoint,
	ctp_e2e_accept,
	ctp_e2e_reject,
	ctp_e2e_connect,
	ctp_e2e_disconnect,
	ctp_e2e_set_opt,
	ctp_e2e_get_opt,
	ctp_e2e_arm_os_handle,
	ctp_e2e_get_event,
	ctp_e2e_return_event,
	ctp_e2e_send,
	ctp_e2e_sendv,
	ctp_e2e_rma_register,
	ctp_e2e_rma_deregister,
	ctp_e2e_rma
};

static int ctp_e2e_init(cci_plugin_ctp_t *plugin, uint32_t abi_ver, uint32_t flags, uint32_t * caps)
{
	int ret = 0;
	struct cci_device *device;
	cci__dev_t *dev = NULL;
	cci_device_t **devices = NULL;

	CCI_ENTER;

	eglobals = calloc(1, sizeof(*eglobals));
	if (!eglobals) {
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	devices = calloc(2, sizeof(*devices));
	if (!devices) {
		ret = CCI_ENOMEM;
		goto out;
	}

	/* Create one e2e virtual device. It will be generic and can
	 * use any native transport.
	 */

	dev = calloc(1, sizeof(*dev));
	if (!dev) {
		ret = CCI_ENOMEM;
		goto out;
	}
	cci__init_dev(dev);
	dev->plugin = plugin;
	dev->priority = plugin->base.priority;

	device = &dev->device;
	device->name = strdup("e2e");
	if (!device->name) {
		ret = CCI_ENOMEM;
		goto out;
	}
	device->transport = strdup("e2e");
	if (!device->transport) {
		ret = CCI_ENOMEM;
		goto out;
	}
	device->up = 1;
	device->max_send_size = 1024; /* do we need a value here? */
	device->rate = 0;

	cci__add_dev(dev);

	devices[0] = device;
	*((cci_device_t ***)&(eglobals->devices)) = devices;
	eglobals->count = 1;
    out:
	if (ret) {
		if (device) {
			free((void*)device->name);
			free((void*)device->transport);
		}
		free(dev);
		free(devices);
		free(eglobals);
	}

	CCI_EXIT;
	return ret;
}

static int ctp_e2e_finalize(cci_plugin_ctp_t * plugin)
{
	CCI_ENTER;

	if (!eglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	free(eglobals->devices);
	free((void*)eglobals);
	eglobals = NULL;

	CCI_EXIT;
	return CCI_SUCCESS;
}

static const char *ctp_e2e_strerror(cci_endpoint_t * endpoint, enum cci_status status)
{
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	e2e_ep_t *eep = ep->priv;

	return cci_strerror(eep->real, status);
}

static int ctp_e2e_create_endpoint(cci_device_t * device,
				    int flags,
				    cci_endpoint_t ** endpointp,
				    cci_os_handle_t * fd)
{
	int ret = 0, i = 0;
	char **arg = NULL, **routers = NULL, *base = NULL;
	uint32_t as = 0, subnet = 0;
	cci__dev_t *dev_e2e = container_of(eglobals->devices[0], cci__dev_t, device);
	cci_endpoint_t *endpoint_real = NULL;
	cci__ep_t *ep_e2e = NULL, *ep_real = NULL;
	e2e_ep_t *eep = NULL;
	char name[256 + 6 + 1]; /* POSIX HOST_NAME_MAX + e2e:// + \0 */

	CCI_ENTER;

	endpoint_real = *endpointp;
	ep_real = container_of(endpoint_real, cci__ep_t, endpoint);

	/* find URI base (after <transport>:// */
	base = strstr(ep_real->uri, "://");
	if (!base) {
		ret = CCI_EINVAL;
		goto out;
	}
	base += 3;

	routers = calloc(CCI_MAX_DEVICES, sizeof(*routers));
	if (!routers) {
		ret = CCI_ENOMEM;
		goto out;
	}

	/* determine if device contains as, subnet, and at least one router */
	for (arg = (char **)device->conf_argv; *arg; arg++) {
		if (0 == strncmp("as=", *arg, 3)) {
			char *as_str = *arg + 3;
			if (as) {
				debug(CCI_DB_EP, "%s: more than one as= in %s's config.",
						__func__, device->name);
				ret = CCI_EINVAL;
				goto out;
			}
			as = strtol(as_str, NULL, 0);
		} else if (0 == strncmp("subnet=", *arg, 7)) {
			char *subnet_str = *arg + 7;
			if (subnet) {
				debug(CCI_DB_EP, "%s: more than one subnet= in %s's config.",
						__func__, device->name);
				ret = CCI_EINVAL;
				goto out;
			}
			subnet = strtol(subnet_str, NULL, 0);
		} else if (0 == strncmp("router=", *arg, 7)) {
			char *router_str = *arg + 7;
			routers[i] = strdup(router_str);
			if (!routers[i]) {
				ret = CCI_ENOMEM;
				goto out;
			}
			i++;
		}
	}

	if (!as || !subnet || !i) {
		if (!as)
			debug(CCI_DB_EP, "%s: no as= in %s's config.", __func__,
					device->name);
		if (!subnet)
			debug(CCI_DB_EP, "%s: no subnet= in %s's config.", __func__,
					device->name);
		if (!i)
			debug(CCI_DB_EP, "%s: no router= in %s's config.", __func__,
					device->name);
		ret = CCI_EINVAL;
		goto out;
	}

	ep_e2e = calloc(1, sizeof(*ep_e2e));
	if (!ep_e2e) {
		ret = CCI_ENOMEM;
		goto out;
	}
	TAILQ_INIT(&ep_e2e->evts);
	pthread_mutex_init(&ep_e2e->lock, NULL);
	ep_e2e->dev = dev_e2e;
	ep_e2e->plugin = dev_e2e->plugin;
	ep_e2e->endpoint.device = &dev_e2e->device;

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name) - 1, "e2e://%u.%u.%s", as, subnet, base);
	ep_e2e->uri = strdup(name);
	if (!ep_e2e->uri) {
		ret = CCI_EINVAL;
		goto out;
	}

	ep_e2e->rx_buf_cnt = ep_real->rx_buf_cnt;
	ep_e2e->tx_buf_cnt = ep_real->tx_buf_cnt;
	ep_e2e->buffer_len = ep_real->buffer_len;
	ep_e2e->tx_timeout = ep_real->tx_timeout;

	ep_e2e->priv = calloc(1, sizeof(*eep));
	if (!ep_e2e->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}
	eep = ep_e2e->priv;

	eep->real = endpoint_real;
	TAILQ_INIT(&eep->idle_txs);
	TAILQ_INIT(&eep->idle_rxs);
	TAILQ_INIT(&eep->idle_rma_frags);
	TAILQ_INIT(&eep->conns);
	TAILQ_INIT(&eep->active);
	TAILQ_INIT(&eep->passive);
	TAILQ_INIT(&eep->closing);
	*((char ***)&eep->routers) = routers;
	eep->as = as;
	eep->subnet = subnet;

	eep->txs = calloc(E2E_TX_CNT, sizeof(*eep->txs));
	if (!eep->txs) {
		ret = CCI_ENOMEM;
		goto out;
	}
	for (i = 0; i < E2E_TX_CNT; i++) {
		e2e_tx_t *tx = &(eep->txs[i]);

		tx->type = E2E_CTX_TX;
		tx->evt.ep = ep_e2e;
		TAILQ_INSERT_TAIL(&eep->idle_txs, &(tx->evt), entry);
	}
	eep->tx_cnt = E2E_TX_CNT;

	eep->rxs = calloc(E2E_RX_CNT, sizeof(*eep->rxs));
	if (!eep->rxs) {
		ret = CCI_ENOMEM;
		goto out;
	}
	for (i = 0; i < E2E_RX_CNT; i++) {
		e2e_rx_t *rx = &(eep->rxs[i]);

		rx->type = E2E_CTX_RX;
		rx->evt.ep = ep_e2e;
		TAILQ_INSERT_TAIL(&eep->idle_rxs, &(rx->evt), entry);
	}
	eep->rx_cnt = E2E_RX_CNT;

	eep->rma_frags = calloc(E2E_RMA_CNT, sizeof(*eep->rma_frags));
	if (!eep->rma_frags) {
		ret = CCI_ENOMEM;
		goto out;
	}
	for (i = 0; i < E2E_RMA_CNT; i++) {
		e2e_rma_frag_t *rma_frag = &(eep->rma_frags[i]);

		rma_frag->type = E2E_CTX_RMA;
		rma_frag->evt.ep = ep_e2e;
		TAILQ_INSERT_TAIL(&eep->idle_rma_frags, &(rma_frag->evt), entry);
	}
	eep->rma_frag_cnt = E2E_RMA_CNT;

	pthread_mutex_lock(&dev_e2e->lock);
	TAILQ_INSERT_TAIL(&dev_e2e->eps, ep_e2e, entry);
	pthread_mutex_unlock(&dev_e2e->lock);

	*endpointp = &ep_e2e->endpoint;

    out:
	if (ret) {
		if (ep_e2e) {
			if (eep) {
				free(eep->rma_frags);
				free(eep->rxs);
				free(eep->txs);
			}
			free(ep_e2e->priv);
			free(ep_e2e->uri);
		}
		free(ep_e2e);
		if (routers) {
			for (arg = (char**) routers; *arg; arg++)
				free(*arg);
		}
		free(routers);
		cci_destroy_endpoint(endpoint_real);
		*endpointp = NULL;
		if (fd)
			*fd = 0;
	}

	CCI_EXIT;
	return ret;
}

static inline e2e_tx_t *
e2e_get_tx_locked(e2e_ep_t *eep)
{
	e2e_tx_t *tx = NULL;

	if (!TAILQ_EMPTY(&eep->idle_txs)) {
		cci__evt_t *evt = TAILQ_FIRST(&eep->idle_txs);
		TAILQ_REMOVE(&eep->idle_txs, evt, entry);
		tx = container_of(evt, e2e_tx_t, evt);
	}
	return tx;
}

static inline e2e_tx_t *
e2e_get_tx(cci__ep_t *ep, int allocate) {
	e2e_ep_t *eep = ep->priv;
	e2e_tx_t *tx = NULL;

	pthread_mutex_lock(&ep->lock);
	tx = e2e_get_tx_locked(eep);
	pthread_mutex_unlock(&ep->lock);

	if (!tx && allocate) {
		do {
			tx = calloc(1, sizeof(*tx));
			tx->type = E2E_CTX_TX;
		} while (!tx);
	}

	return tx;
}

static inline void
e2e_put_tx_locked(e2e_ep_t *eep, e2e_tx_t *tx)
{
	tx->evt.conn = NULL;
	tx->msg_type = CCI_E2E_MSG_INVALID;
	tx->state = E2E_TX_IDLE;
	tx->seq = 0;
	tx->rma = NULL;
	TAILQ_INSERT_HEAD(&eep->idle_txs, &(tx->evt), entry);

	return;
}

static inline void
e2e_put_tx(e2e_tx_t *tx)
{
	cci__ep_t *ep = tx->evt.ep;
	e2e_ep_t *eep = ep->priv;

	if (tx->evt.ep) {
		pthread_mutex_lock(&ep->lock);
		e2e_put_tx_locked(eep, tx);
		pthread_mutex_unlock(&ep->lock);
	} else {
		free(tx);
	}

	return;
}

static inline e2e_rx_t *
e2e_get_rx_locked(e2e_ep_t *eep)
{
	e2e_rx_t *rx = NULL;

	if (!TAILQ_EMPTY(&eep->idle_rxs)) {
		cci__evt_t *evt = TAILQ_FIRST(&eep->idle_rxs);
		TAILQ_REMOVE(&eep->idle_rxs, evt, entry);
		rx = container_of(evt, e2e_rx_t, evt);
		rx->evt.conn = NULL;
		rx->msg_type = CCI_E2E_MSG_INVALID;
		rx->seq = 0;
	}
	return rx;
}

static inline e2e_rx_t *
e2e_get_rx(cci__ep_t *ep) {
	e2e_ep_t *eep = ep->priv;
	e2e_rx_t *rx = NULL;

	pthread_mutex_lock(&ep->lock);
	rx = e2e_get_rx_locked(eep);
	pthread_mutex_unlock(&ep->lock);

	return rx;
}

static inline void
e2e_put_rx_locked(e2e_ep_t *eep, e2e_rx_t *rx)
{
	rx->evt.conn = NULL;
	rx->msg_type = CCI_E2E_MSG_INVALID;
	rx->seq = 0;
	TAILQ_INSERT_HEAD(&eep->idle_rxs, &(rx->evt), entry);

	return;
}

static inline void
e2e_put_rx(e2e_rx_t *rx)
{
	cci__ep_t *ep = rx->evt.ep;
	e2e_ep_t *eep = ep->priv;

	pthread_mutex_lock(&ep->lock);
	e2e_put_rx_locked(eep, rx);
	pthread_mutex_unlock(&ep->lock);

	return;
}

static inline e2e_rma_frag_t *
e2e_get_rma_frag_locked(e2e_ep_t *eep)
{
	e2e_rma_frag_t *rma_frag = NULL;

	if (!TAILQ_EMPTY(&eep->idle_rma_frags)) {
		cci__evt_t *evt = TAILQ_FIRST(&eep->idle_rma_frags);
		TAILQ_REMOVE(&eep->idle_rma_frags, evt, entry);
		rma_frag = container_of(evt, e2e_rma_frag_t, evt);
	}
	return rma_frag;
}

static inline e2e_rma_frag_t *
e2e_get_rma_frag(cci__ep_t *ep) {
	e2e_ep_t *eep = ep->priv;
	e2e_rma_frag_t *rma_frag = NULL;

	pthread_mutex_lock(&ep->lock);
	rma_frag = e2e_get_rma_frag_locked(eep);
	pthread_mutex_unlock(&ep->lock);

	return rma_frag;
}

static inline void
e2e_put_rma_frag_locked(e2e_ep_t *eep, e2e_rma_frag_t *rma_frag)
{
	rma_frag->evt.conn = NULL;
	rma_frag->rma = NULL;
	rma_frag->id = 0;
	TAILQ_INSERT_HEAD(&eep->idle_rma_frags, &(rma_frag->evt), entry);

	return;
}

static inline void
e2e_put_rma_frag(e2e_rma_frag_t *rma_frag)
{
	cci__ep_t *ep = rma_frag->evt.ep;
	e2e_ep_t *eep = ep->priv;

	pthread_mutex_lock(&ep->lock);
	e2e_put_rma_frag_locked(eep, rma_frag);
	pthread_mutex_unlock(&ep->lock);

	return;
}

static int ctp_e2e_destroy_endpoint(cci_endpoint_t * endpoint)
{
	int ret = 0;
	char **router = NULL;
	cci__ep_t *ep = NULL;
	e2e_ep_t *eep = NULL;

	CCI_ENTER;

	if (!eglobals)
		return CCI_ENODEV;

	ep = container_of(endpoint, cci__ep_t, endpoint);
	eep = ep->priv;

	ret = cci_destroy_endpoint(eep->real);
	if (ret) {
		cci__ep_t *ep_real = container_of(eep->real, cci__ep_t, endpoint);

		debug(CCI_DB_EP, "%s: when destroying e2e endpoint %s's "
			"real endpoint %s, it failed with %s", __func__,
			ep->uri, ep_real->uri, cci_strerror(eep->real, ret));
	}

	for (router = (char **)eep->routers; *router; router++)
		free(*router);
	free((void **)eep->routers);

	if (ep->priv) {
		e2e_ep_t *eep = ep->priv;

		free(eep->rma_frags);
		free(eep->rxs);
		free(eep->txs);
	}
	free(ep->priv);
	free(ep->uri);

	CCI_EXIT;
	return ret;
}

static void
e2e_send_bye(cci__ep_t *ep, cci__conn_t *conn, int flags)
{
	int ret = 0;
	e2e_ep_t *eep = ep->priv;
	e2e_conn_t *econn = conn->priv;
	cci_e2e_hdr_t hdr;

	cci_e2e_pack_bye(&hdr);

	ret = cci_send(econn->real, &hdr, sizeof(hdr.bye), NULL, flags);
	if (ret)
		debug(CCI_DB_CONN, "%s: send bye failed with %s", __func__,
			cci_strerror(eep->real, ret));

	return;
}

static int
e2e_send_conn_reply(cci__ep_t *ep, cci__conn_t *conn, uint8_t status)
{
	int ret = 0;
	e2e_ep_t *eep = ep->priv;
	e2e_conn_t *econn = conn->priv;
	cci_e2e_hdr_t reply;
	e2e_tx_t *tx = NULL;

	tx = e2e_get_tx(ep, 1);
	/* do not set tx->evt.ep - we will free this when it completes */
	tx->evt.conn = conn;
	tx->msg_type = CCI_E2E_MSG_CONN_REPLY;
	tx->state = E2E_TX_PENDING;

	cci_e2e_pack_connect_reply(&reply, status, econn->real->max_send_size, E2E_RMA_MTU);

	ret = cci_send(econn->real, &reply, sizeof(reply.conn_reply), (void*)tx, 0);
	if (ret)
		debug(CCI_DB_CONN, "%s: send conn_reply returned %s",
			__func__, cci_strerror(eep->real, ret));

	if (ret)
		e2e_put_tx(tx);

	return ret;
}

static int
e2e_send_conn_ack(cci__ep_t *ep, cci__conn_t *conn)
{
	int ret = 0;
	e2e_ep_t *eep = ep->priv;
	e2e_conn_t *econn = conn->priv;
	cci_e2e_hdr_t ack;
	e2e_tx_t *tx = NULL;

	tx = e2e_get_tx(ep, 1);
	/* do not set tx->evt.ep - we will free this when it completes */
	tx->evt.conn = conn;
	tx->msg_type = CCI_E2E_MSG_CONN_ACK;
	tx->state = E2E_TX_PENDING;

	cci_e2e_pack_connect_ack(&ack, conn->connection.max_send_size, econn->rma_mtu);

	ret = cci_send(econn->real, &ack, sizeof(ack.conn_ack), (void*)tx, 0);
	if (ret)
		debug(CCI_DB_CONN, "%s: send conn_ack returned %s",
			__func__, cci_strerror(eep->real, ret));

	if (ret)
		e2e_put_tx(tx);

	return ret;
}

static int ctp_e2e_accept(cci_event_t *event, const void *context)
{
	int ret = 0;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	cci__evt_t *evt = NULL;
	e2e_ep_t *eep = NULL;
	e2e_conn_t *econn = NULL;

	CCI_ENTER;

	evt = container_of(event, cci__evt_t, event);
	ep = evt->ep;
	eep = ep->priv;

	conn = evt->conn;
	econn = conn->priv;

	conn->connection.context = (void*) context;

	if (econn->real) {
		/* we have the real connection, send the e2e connect reply */
		assert(econn->state == E2E_CONN_PASSIVE2);

		ret = e2e_send_conn_reply(ep, conn, CCI_SUCCESS);
		if (ret) {
			assert(0);
			/* TODO */
		}
	} else {
		/* still waiting on native accept event */
		econn->state |= E2E_CONN_PASSIVE2;
	}

	CCI_EXIT;
	return ret;
}

static int ctp_e2e_reject(cci_event_t *event)
{
	CCI_ENTER;

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_connect(cci_endpoint_t * endpoint, const char *server_uri,
			    const void *data_ptr, uint32_t data_len,
			    cci_conn_attribute_t attribute,
			    const void *context, int flags, const struct timeval *timeout)
{
	int ret = 0;
	uint32_t len = 0, total_len = 0, as = 0, subnet = 0;
	const char *base = NULL, *uri = server_uri;
	char *local_uri = NULL;
	cci__ep_t *ep = NULL, *ep_real = NULL;
	cci__conn_t *conn = NULL;
	e2e_ep_t *eep = NULL;
	e2e_conn_t *econn = NULL;
	/* e2e_tx_t *tx = NULL; */
	void *buf = NULL;
	cci_e2e_hdr_t *hdr = NULL;

	CCI_ENTER;

	if (!eglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	eep = ep->priv;
	ep_real =container_of(eep->real, cci__ep_t, endpoint);

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		CCI_EXIT;
		return CCI_ENOMEM;
	}
	conn->plugin = ep->plugin;

	conn->connection.max_send_size = eep->real->device->max_send_size;
	conn->connection.endpoint = endpoint;
	conn->connection.attribute = attribute;
	conn->connection.context = (void*) context;

	conn->uri = strdup(server_uri);
	if (!conn->uri) {
		ret = CCI_ENOMEM;
		goto out;
	}
	conn->tx_timeout = ep->tx_timeout;
	conn->priv = calloc(1, sizeof(*econn));
	if (!conn->priv) {
		ret = CCI_ENOMEM;
		goto out;
	}
	econn = conn->priv;
	econn->conn = conn;
	econn->state = E2E_CONN_ACTIVE1;
	TAILQ_INIT(&econn->pending);

	/* this is large by 4 bytes, it is ok */
	total_len = sizeof(hdr->connect_size) + sizeof(cci_e2e_connect_t) + data_len;
	total_len += strlen(ep->uri) + strlen(server_uri);

	buf = calloc(1, total_len);
	if (!buf) {
		ret = CCI_ENOMEM;
		goto out;
	}
	hdr = buf;

	cci_e2e_pack_connect(hdr, server_uri, ep->uri, data_ptr, data_len, &len);

	/* Is the peer a router or a native user? */
	ret = cci_e2e_parse_uri(server_uri, &as, &subnet, &base);
	if (ret)
		goto out;

	if (subnet == eep->subnet) {
		int prefix_len = 0, base_len = 0, len = 0;

		/* build local URI for non-routed connection */
		ret = cci_e2e_uri_prefix_len(ep_real->uri, &prefix_len);
		if (ret)
			goto out;

		base_len = strlen(base);
		len = prefix_len + base_len;

		local_uri = calloc(1, len + 1); /* len + \0 */
		if (!local_uri) {
			ret = CCI_ENOMEM;
			goto out;
		}
		snprintf(local_uri, prefix_len + 1, "%s", ep_real->uri);
		snprintf(local_uri + prefix_len, base_len + 1, "%s", base);

		uri = local_uri;
	} else {
		/* send to a router */
		/* TODO round-robin over eep->routers */
		uri = eep->routers[0];
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&eep->active, econn, entry);
	pthread_mutex_unlock(&ep->lock);

	ret = cci_connect(eep->real, uri, hdr, len, attribute, (void*)conn,
			flags, timeout);

	if (ret) {
		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&eep->active, econn, entry);
		pthread_mutex_unlock(&ep->lock);
	}
    out:
	free(buf);
	free(local_uri);
	if (ret) {
		if (conn) {
			free(conn->priv);
			free((void*)conn->uri);
		}
		free(conn);
	}

	CCI_EXIT;
	return ret;
}

static int ctp_e2e_disconnect(cci_connection_t * connection)
{
	CCI_ENTER;

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_set_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, const void *val)
{
	CCI_ENTER;

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_get_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, void *val)
{
	CCI_ENTER;

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_arm_os_handle(cci_endpoint_t * endpoint, int flags)
{
	CCI_ENTER;

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int
e2e_handle_native_connect(cci__ep_t *ep, cci_event_t *native_event, cci_event_t **new)
{
	int ret = 0;
	cci__conn_t *conn = native_event->connect.context;
	e2e_conn_t *econn = conn->priv;
	e2e_ep_t *eep = ep->priv;

	if (native_event->connect.status == CCI_SUCCESS) {
		econn->real = native_event->connect.connection;
		econn->state = E2E_CONN_ACTIVE2;
		*new = NULL;
		ret = CCI_EAGAIN;
	} else {
		cci__evt_t *evt = calloc(1, sizeof(*evt));
		if (!evt) {
			/* FIXME */
			return CCI_EAGAIN;
		}
		evt->event.connect.type = CCI_EVENT_CONNECT;
		evt->event.connect.status = native_event->connect.status;
		evt->event.connect.context = conn->connection.context;
		evt->event.connect.connection = NULL;
		evt->ep = ep;
		evt->conn = NULL;
		*new = &evt->event;
		ret = CCI_SUCCESS;

		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&eep->active, econn, entry);
		pthread_mutex_unlock(&ep->lock);

		free(conn->priv);
		free((void*)conn->uri);
		free(conn);
	}

	return ret;
}

/* We have received an e2e connect request.
 * Validate the e2e header.
 * Alloc e2e connection.
 * Accept the native connection.
 * Generate the e2e connect request event.
 */
static int
e2e_handle_native_connect_request(cci__ep_t *ep, cci_event_t *native_event, cci_event_t **new)
{
	int ret = 0;
	char dst[256], src[256];
	uint32_t e2e_len = 0, len = 0;
	void *ptr = NULL;
	cci_e2e_hdr_t *hdr = (void *)native_event->request.data_ptr;
	cci_e2e_connect_t *connect = NULL;
	cci__conn_t *conn = NULL;
	e2e_ep_t *eep = ep->priv;
	e2e_conn_t *econn = NULL;
	cci__evt_t *evt = NULL;

	e2e_len = sizeof(hdr->connect_size) + sizeof(connect->size);

	if (native_event->request.data_len < e2e_len) {
		debug(CCI_DB_CONN, "%s: invalid connection request. Length %u is too small",
			__func__, native_event->request.data_len);
		ret = CCI_EINVAL;
		goto out;
	}

	ret = cci_e2e_parse_connect(hdr, dst, src, &ptr, &len);
	if (ret) {
		debug(CCI_DB_CONN, "%s: no memory for payload", __func__);
		ret = CCI_ENOMEM;
		goto out;
	}

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		debug(CCI_DB_CONN, "%s: no memory for new conn", __func__);
		ret = CCI_ENOMEM;
		goto out;
	}
	conn->plugin = ep->plugin;
	conn->connection.endpoint = &(ep->endpoint);
	conn->connection.attribute = native_event->request.attribute;
	/* conn->connection.max_send_size will be set in conn_reply */

	conn->priv = calloc(1, sizeof(*econn));
	if (!conn->priv) {
		debug(CCI_DB_CONN, "%s: no memory for new econn", __func__);
		ret = CCI_ENOMEM;
		goto out;
	}
	econn = conn->priv;
	econn->conn = conn;
	econn->state = E2E_CONN_PASSIVE1;
	TAILQ_INIT(&econn->pending);

	evt = calloc(1, sizeof(*evt));
	if (!evt) {
		debug(CCI_DB_CONN, "%s: no memory for new event", __func__);
		ret = CCI_ENOMEM;
		goto out;
	}

	evt->event.request.type = CCI_EVENT_CONNECT_REQUEST;
	evt->event.request.data_len = len;
	evt->event.request.data_ptr = ptr; /* need to free this later */
	evt->event.request.attribute = native_event->request.attribute;
	evt->ep = ep;
	evt->conn = conn;

	ret = cci_accept(native_event, conn);
	if (ret) {
		debug(CCI_DB_CONN, "%s: native accept failed with %s", __func__,
				cci_strerror(eep->real, ret));
		goto out;
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&eep->passive, econn, entry);
	pthread_mutex_unlock(&ep->lock);

	*new = &(evt->event);
	ret = CCI_SUCCESS;

    out:
	if (ret) {
		free(evt);
		if (conn)
			free(conn->priv);
		free(conn);
		free(ptr);
		*new = NULL;
	}
	return ret;
}

/* We have received a native accept event.
 * If successful, store real connection.
 * If not, free connection, generate e2e accept event
 */
static int
e2e_handle_native_accept(cci__ep_t *ep, cci_event_t *native_event, cci_event_t **new)
{
	int ret = 0;
	cci__conn_t *conn = native_event->connect.context;
	e2e_conn_t *econn = conn->priv;
	e2e_ep_t *eep = ep->priv;

	if (native_event->accept.status == CCI_SUCCESS) {
		econn->real = native_event->accept.connection;
		if (econn->state & E2E_CONN_PASSIVE2) {
			/* User has called accept(), send e2e conn reply */
			ret = e2e_send_conn_reply(ep, conn, CCI_SUCCESS);
			if (ret) {
				/* TODO */
				assert(0);
			}
		}
		econn->state = E2E_CONN_PASSIVE2;
		*new = NULL;
		ret = CCI_EAGAIN;
	} else {
		e2e_tx_t *tx = NULL;

		tx = e2e_get_tx(ep, 1);
		tx->msg_type = CCI_E2E_MSG_CONN_REPLY;
		tx->state = E2E_TX_COMPLETED;
		tx->evt.event.accept.type = CCI_EVENT_ACCEPT;
		tx->evt.event.accept.status = CCI_ERR_DISCONNECTED;
		tx->evt.event.accept.context = conn->connection.context;
		tx->evt.event.accept.connection = NULL;
		*new = &(tx->evt.event);

		ret = CCI_SUCCESS;

		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&eep->passive, econn, entry);
		pthread_mutex_unlock(&ep->lock);

		free(conn->priv);
		free((void*)conn->uri);
		free(conn);
	}

	return ret;
}

/* We have received a native send event.
 * If reliable and successful, ignore and return tx.
 * If reliable and failed, generate send event.
 * If unreliable, generate send event.
 */
static int
e2e_handle_native_send(cci__ep_t *ep, cci_event_t *native_event, cci_event_t **new)
{
	int ret = CCI_EAGAIN;
	e2e_tx_t *tx = native_event->send.context;
	cci__conn_t *conn = NULL;

	*new = NULL;

	if (!tx)
		return CCI_EAGAIN;

	conn = tx->evt.conn;

	switch (tx->msg_type) {
	case CCI_E2E_MSG_CONN_REPLY:
		if (native_event->send.status != CCI_SUCCESS) {
			/* The conn reply failed.
			 * Generate ACCEPT event with failed status.
			 */
			tx->evt.event.accept.type = CCI_EVENT_ACCEPT;
			tx->evt.event.accept.status = CCI_ERR_DISCONNECTED;
			tx->evt.event.accept.context = conn->connection.context;
			tx->evt.event.accept.connection = NULL;
			*new = &(tx->evt.event);
			ret = CCI_SUCCESS;
		} else {
			e2e_put_tx(tx);
		}
		break;
	case CCI_E2E_MSG_CONN_ACK:
		e2e_put_tx(tx);
		break;
	case CCI_E2E_MSG_SEND:
		if (!cci_conn_is_reliable(conn) ||
			native_event->send.status != CCI_SUCCESS) {

			/* complete now with error, otherwise wait for e2e ack */
			tx->evt.event.send.status = native_event->send.status;
			*new = &(tx->evt.event);
			ret = CCI_SUCCESS;

			if (cci_conn_is_reliable(conn)) {
				e2e_conn_t *econn = conn->priv;

				pthread_mutex_lock(&ep->lock);
				TAILQ_REMOVE(&econn->pending, &(tx->evt), entry);
				pthread_mutex_unlock(&ep->lock);
			}
		}
		break;
	default:
		debug(CCI_DB_MSG, "%s: ignoring %s send completion", __func__,
			cci_e2e_msg_type_str(tx->msg_type));
	}

	return ret;
}

static int
e2e_handle_conn_reply(cci__ep_t *ep, cci_event_t *native_event, cci_event_t **new)
{
	int ret = 0;
	uint8_t status = 0;
	uint16_t mss = 0;
	uint32_t mtu = 0;
	cci_connection_t *connection = native_event->recv.connection;
	cci__conn_t *conn = connection->context;
	e2e_conn_t *econn = conn->priv;
	e2e_ep_t *eep = ep->priv;
	cci_e2e_hdr_t *hdr = (void *)native_event->recv.ptr;
	cci__evt_t *evt = NULL;

	*new = NULL;

	if (native_event->recv.len != sizeof(hdr->conn_reply)) {
		debug(CCI_DB_CONN, "%s: invalid conn reply size of %u", __func__,
			native_event->recv.len);
		ret = CCI_EINVAL;
		/* TODO */
		assert(native_event->recv.len == sizeof(hdr->conn_reply));
	}

	cci_e2e_parse_connect_reply(hdr, &status, &mss, &mtu);

	conn->connection.max_send_size = mss - sizeof(hdr->net[0]);

	evt = calloc(1, sizeof(*evt));
	if (!evt) {
		/* FIXME */
		return CCI_EAGAIN;
	}
	evt->event.connect.type = CCI_EVENT_CONNECT;
	evt->event.connect.status = status;
	evt->event.connect.context = conn->connection.context;
	evt->ep = ep;
	evt->conn = NULL;
	*new = &evt->event;

	if (!status) {
		/* SUCCESS */
		evt->event.connect.connection = &conn->connection;;
		econn->state = E2E_CONN_CONNECTED;
		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&eep->active, econn, entry);
		TAILQ_INSERT_TAIL(&eep->conns, econn, entry);
		pthread_mutex_unlock(&ep->lock);

		/* FIXME use ret2? */
		/* send conn_ack */
		ret = e2e_send_conn_ack(ep, conn);
		if (ret)
			debug(CCI_DB_CONN, "%s: send conn_ack failed with %s", __func__,
				cci_strerror(eep->real, ret));
	} else {
		/* REJECTED */
		evt->event.connect.connection = NULL;
		pthread_mutex_lock(&ep->lock);
		TAILQ_REMOVE(&eep->active, econn, entry);
		pthread_mutex_unlock(&ep->lock);

		e2e_send_bye(ep, conn, CCI_FLAG_BLOCKING);

		/* FIXME use ret2? */
		ret = cci_disconnect(econn->real);
		if (ret)
			debug(CCI_DB_CONN, "%s: disconnect failed with %s",
				__func__, cci_strerror(eep->real, ret));
		free(conn->priv);
		free((void*)conn->uri);
		free(conn);
	}

	return ret;
}

static int
e2e_handle_conn_ack(cci__ep_t *ep, cci_event_t *native_event, cci_event_t **new)
{
	int ret = 0;
	uint16_t mss = 0;
	uint32_t mtu = 0;
	cci_connection_t *connection = native_event->recv.connection;
	cci__conn_t *conn = connection->context;
	cci__evt_t *evt = NULL;
	e2e_conn_t *econn = conn->priv;
	e2e_ep_t *eep = ep->priv;
	cci_e2e_hdr_t *hdr = (void *)native_event->recv.ptr;

	*new = NULL;

	if (native_event->recv.len != sizeof(hdr->conn_ack)) {
		debug(CCI_DB_CONN, "%s: invalid conn ack size of %u", __func__,
			native_event->recv.len);
		ret = CCI_EINVAL;
		/* TODO */
		assert(native_event->recv.len == sizeof(hdr->conn_ack));
	}

	cci_e2e_parse_connect_ack(hdr, &mss, &mtu);

	conn->connection.max_send_size = mss - sizeof(hdr->net[0]);
	econn->rma_mtu = mtu;

	evt = calloc(1, sizeof(*evt));
	if (!evt) {
		/* FIXME */
		return CCI_EAGAIN;
	}
	evt->event.accept.type = CCI_EVENT_ACCEPT;
	evt->event.accept.status = CCI_SUCCESS;
	evt->event.accept.context = conn->connection.context;
	evt->event.accept.connection = &(conn->connection);
	evt->ep = ep;
	evt->conn = NULL;
	*new = &evt->event;

	econn->state = E2E_CONN_CONNECTED;

	pthread_mutex_lock(&ep->lock);
	TAILQ_REMOVE(&eep->passive, econn, entry);
	TAILQ_INSERT_TAIL(&eep->conns, econn, entry);
	pthread_mutex_unlock(&ep->lock);

	return ret;
}

static int
e2e_handle_send_ack(cci__ep_t *ep, cci_event_t *native_event, cci_event_t **new)
{
	int ret = CCI_EAGAIN;
	uint16_t seq = 0;
	cci_connection_t *connection = native_event->recv.connection;
	cci__conn_t *conn = connection->context;
	cci__evt_t *evt = NULL;
	e2e_conn_t *econn = conn->priv;
	e2e_tx_t *tx = NULL;
	cci_e2e_hdr_t *hdr = (void *)native_event->recv.ptr;

	*new = NULL;

	if (native_event->recv.len != sizeof(hdr->send_ack)) {
		debug(CCI_DB_CONN, "%s: invalid send ack size of %u", __func__,
			native_event->recv.len);
		/* TODO */
		assert(native_event->recv.len == sizeof(hdr->conn_ack));
	}

	cci_e2e_parse_send_ack(hdr, &seq);

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(evt, &econn->pending, entry) {
		tx = container_of(evt, e2e_tx_t, evt);
		if (tx->seq == seq) {
			TAILQ_REMOVE(&econn->pending, evt, entry);
			*new = &(evt->event);
			ret = CCI_SUCCESS;
			break;
		}
	}
	pthread_mutex_unlock(&ep->lock);

	if (ret) {
		debug(CCI_DB_MSG, "%s: no matching send for ack %u from %s", __func__,
			seq, conn->uri);
	}

	return ret;
}

static int
e2e_handle_recv(cci__ep_t *ep, cci_event_t *native_event, cci_event_t **new, int *recycle)
{
	int ret = CCI_EAGAIN;
	uint16_t seq = 0;
	cci_connection_t *connection = native_event->recv.connection;
	cci__conn_t *conn = connection->context;
	e2e_conn_t *econn = conn->priv;
	cci_e2e_hdr_t *hdr = (void *)native_event->recv.ptr, ack;
	e2e_rx_t *rx = NULL;

	*new = NULL;

	cci_e2e_parse_send(hdr, &seq);

	rx = e2e_get_rx(ep);
	if (!rx) {
		/* TODO */
		assert(rx);
	}

	rx->evt.event.recv.type = CCI_EVENT_RECV;
	rx->evt.event.recv.ptr = (void*)(hdr->send.data);
	rx->evt.event.recv.len = native_event->recv.len - sizeof(hdr->send_size);
	rx->evt.event.recv.connection = &(conn->connection);
	rx->evt.ep = ep;
	rx->evt.conn = conn;
	rx->msg_type = CCI_E2E_MSG_SEND;
	rx->seq = seq;
	rx->native = native_event;

	/* TODO ack seq */

	ret = CCI_SUCCESS;
	*new = &(rx->evt.event);
	*recycle = 0;

	if (cci_conn_is_reliable(conn)) {
		int ret2 = 0;

		cci_e2e_pack_send_ack(&ack, rx->seq);
		ret2 = cci_send(econn->real, &ack, sizeof(ack.send_ack), NULL, CCI_FLAG_SILENT);
		if (ret2) {
			e2e_ep_t *eep = ep->priv;

			debug(CCI_DB_MSG, "%s: sending ack %u to %s failed with %s", __func__,
				rx->seq, conn->uri, cci_strerror(eep->real, ret2));
			assert(ret2 == 0);
		}
	}

	return ret;
}

static int
e2e_handle_native_recv(cci__ep_t *ep, cci_event_t *native_event, cci_event_t **new, int *recycle)
{
	int ret = CCI_EAGAIN;
	cci_e2e_hdr_t *hdr = (void *)native_event->recv.ptr;

	if (native_event->recv.len < sizeof(hdr->generic)) {
		debug(CCI_DB_MSG, "%s: recv'd runt with len %u",
			__func__, native_event->recv.len);
		return CCI_EAGAIN;
	}

	hdr->net[0] = ntohl(hdr->net[0]);

	switch (hdr->generic.type) {
	case CCI_E2E_MSG_CONN_REPLY:
		ret = e2e_handle_conn_reply(ep, native_event, new);
		break;
	case CCI_E2E_MSG_CONN_ACK:
		ret = e2e_handle_conn_ack(ep, native_event, new);
		break;
	case CCI_E2E_MSG_SEND:
		ret = e2e_handle_recv(ep, native_event, new, recycle);
		break;
	case CCI_E2E_MSG_SEND_ACK:
		ret = e2e_handle_send_ack(ep, native_event, new);
		break;
	default:
		debug(CCI_DB_MSG, "%s: ignoring %s (0x%x) recv completion", __func__,
			cci_e2e_msg_type_str(hdr->generic.type), hdr->net[0]);
	}

	return ret;
}

static int ctp_e2e_get_event(cci_endpoint_t * endpoint,
			      cci_event_t ** event)
{
	int ret = CCI_EAGAIN;
	cci__ep_t *ep = NULL;
	e2e_ep_t *eep = NULL;
	cci_event_t *native_event = NULL;

	CCI_ENTER;

	if (!eglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	eep = ep->priv;

	ret = cci_get_event(eep->real, &native_event);
	if (ret == CCI_SUCCESS) {
		int recycle = 1;

		debug(CCI_DB_EP, "%s: found %s", __func__,
				cci_event_type_str(native_event->type));

		switch (native_event->type) {
		case CCI_EVENT_CONNECT:
			ret = e2e_handle_native_connect(ep, native_event, event);
			break;
		case CCI_EVENT_CONNECT_REQUEST:
			ret = e2e_handle_native_connect_request(ep, native_event, event);
			break;
		case CCI_EVENT_ACCEPT:
			ret = e2e_handle_native_accept(ep, native_event, event);
			break;
		case CCI_EVENT_SEND:
			ret = e2e_handle_native_send(ep, native_event, event);
			break;
		case CCI_EVENT_RECV:
			ret = e2e_handle_native_recv(ep, native_event, event, &recycle);
			break;
		default:
			debug(CCI_DB_EP, "%s: ignoring %s", __func__,
				cci_event_type_str(native_event->type));
			break;
		}
		if (recycle) {
			int ret2 = cci_return_event(native_event);
			if (ret2)
				debug(CCI_DB_EP, "%s: native return_event failed with %s",
					__func__, cci_strerror(eep->real, ret2));
		}
	}

	CCI_EXIT;
	return ret;
}

static int ctp_e2e_return_event(cci_event_t * event)
{
	int ret = 0;

	CCI_ENTER;

	switch (event->type) {
	case CCI_EVENT_CONNECT:
	{
		cci__evt_t *evt = container_of(event, cci__evt_t, event);
		free(evt);
		break;
	}
	case CCI_EVENT_CONNECT_REQUEST:
	{
		cci__evt_t *evt = container_of(event, cci__evt_t, event);
		cci__conn_t *conn = evt->conn;
		e2e_conn_t *econn = conn->priv;

		debug(CCI_DB_CONN, "%s: freeing conn request %p date_ptr %p len %u",
			__func__, (void*)evt, evt->event.request.data_ptr,
			evt->event.request.data_len);

		if (!(econn->state & E2E_CONN_PASSIVE2))
			ret = CCI_EINVAL;

		/* This was alloced in e2e_handle_native_connect_request().
		 * Free it now */
		free((void*)evt->event.request.data_ptr);
		free(evt);
		break;
	}
	case CCI_EVENT_ACCEPT:
	{
		cci__evt_t *evt = container_of(event, cci__evt_t, event);

		if (event->accept.status != CCI_SUCCESS) {
			e2e_tx_t *tx = container_of(evt, e2e_tx_t, evt);
			e2e_put_tx(tx);
		} else {
			/* This was alloced in e2e_handle_conn_ack() */
			free(evt);
		}
		break;
	}
	case CCI_EVENT_RECV:
	{
		int ret2 = 0;
		cci__evt_t *evt = container_of(event, cci__evt_t, event);
		e2e_rx_t *rx = container_of(evt, e2e_rx_t, evt);

		ret2 = cci_return_event(rx->native);
		if (ret2) {
			cci__ep_t *ep = evt->ep;
			e2e_ep_t *eep = ep->priv;

			debug(CCI_DB_MSG, "%s: return native event returned %s",
				__func__, cci_strerror(eep->real, ret));
		}

		e2e_put_rx(rx);
		break;
	}
	case CCI_EVENT_SEND:
	{
		cci__evt_t *evt = container_of(event, cci__evt_t, event);
		e2e_tx_t *tx = container_of(evt, e2e_tx_t, evt);

		e2e_put_tx(tx);
		break;
	}
	default:
		break;
	}

	CCI_EXIT;
	return ret;
}

static inline uint16_t
e2e_conn_next_seq(cci__ep_t *ep, cci__conn_t *conn)
{
	uint16_t seq = 0;
	e2e_conn_t *econn = conn->priv;

	pthread_mutex_lock(&ep->lock);
	seq = ++econn->seq;
	pthread_mutex_unlock(&ep->lock);

	return seq;
}

static int ctp_e2e_send(cci_connection_t * connection,
			 const void *msg_ptr, uint32_t msg_len,
			 const void *context, int flags)
{
	int ret = 0;
	cci__ep_t *ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	cci__conn_t *conn = container_of(connection, cci__conn_t, connection);
	e2e_conn_t *econn = conn->priv;
	e2e_tx_t *tx = NULL;
	cci_e2e_hdr_t hdr;
	struct iovec iov[2];
	uint32_t iov_cnt = msg_len ? 2 : 1;

	CCI_ENTER;

	if (!eglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	tx = e2e_get_tx(ep, 0);
	if (!tx) {
		CCI_EXIT;
		return CCI_ENOBUFS;
	}

	tx->evt.event.send.type = CCI_EVENT_SEND;
	tx->evt.event.send.status = CCI_SUCCESS; /* for now */
	tx->evt.event.send.connection = connection;
	tx->evt.event.send.context = (void*)context;
	/* tx->evt.ep = ep; already set */
	tx->evt.conn = conn;
	tx->msg_type = CCI_E2E_MSG_SEND;
	tx->state = E2E_TX_PENDING;
	tx->flags = flags;
	tx->seq = e2e_conn_next_seq(ep, conn);
	/* tx->rma = NULL; already set */

	cci_e2e_pack_send(&hdr, tx->seq);

	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr.send_size);

	if (msg_len) {
		iov[1].iov_base = (void*)msg_ptr;
		iov[1].iov_len = msg_len;
	}

	if (cci_conn_is_reliable(conn) && !(flags & CCI_FLAG_BLOCKING)) {
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&econn->pending, &(tx->evt), entry);
		pthread_mutex_unlock(&ep->lock);
	}

	ret = cci_sendv(econn->real, iov, iov_cnt, (void*)tx, flags);
	if (ret) {
		if (cci_conn_is_reliable(conn) && !(flags & CCI_FLAG_BLOCKING)) {
			pthread_mutex_lock(&ep->lock);
			TAILQ_REMOVE(&econn->pending, &(tx->evt), entry);
			pthread_mutex_unlock(&ep->lock);
		}
		e2e_put_tx(tx);
		goto out;
	}

    out:
	CCI_EXIT;
	return ret;
}

static int ctp_e2e_sendv(cci_connection_t * connection,
			  const struct iovec *data, uint32_t iovcnt,
			  const void *context, int flags)
{
	int ret = 0, i = 0;
	cci__ep_t *ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	cci__conn_t *conn = container_of(connection, cci__conn_t, connection);
	e2e_conn_t *econn = conn->priv;
	e2e_tx_t *tx = NULL;
	cci_e2e_hdr_t hdr;
	struct iovec *iov = NULL;

	CCI_ENTER;

	if (!eglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	tx = e2e_get_tx(ep, 0);
	if (!tx) {
		CCI_EXIT;
		return CCI_ENOBUFS;
	}

	tx->evt.event.send.type = CCI_EVENT_SEND;
	tx->evt.event.send.status = CCI_SUCCESS; /* for now */
	tx->evt.event.send.connection = connection;
	tx->evt.event.send.context = (void*)context;
	/* tx->evt.ep = ep; already set */
	tx->evt.conn = conn;
	tx->msg_type = CCI_E2E_MSG_SEND;
	tx->state = E2E_TX_PENDING;
	tx->flags = flags;
	tx->seq = e2e_conn_next_seq(ep, conn);
	/* tx->rma = NULL; already set */

	cci_e2e_pack_send(&hdr, tx->seq);

	iov = calloc(iovcnt + 1, sizeof(*iov)); /* iovcnt + hdr */
	if (!iov) {
		ret = CCI_ENOMEM;
		goto out;
	}

	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr.send_size);

	for (i = 1; i < (int) iovcnt + 1; i++) {
		iov[i].iov_base = data[i - 1].iov_base;
		iov[i].iov_len = data[i - 1].iov_len;
	}

	if (cci_conn_is_reliable(conn) && !(flags & CCI_FLAG_BLOCKING)) {
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&econn->pending, &(tx->evt), entry);
		pthread_mutex_unlock(&ep->lock);
	}

	ret = cci_sendv(econn->real, iov, iovcnt + 1, (void*)tx, flags);
	if (ret) {
		if (cci_conn_is_reliable(conn) && !(flags & CCI_FLAG_BLOCKING)) {
			pthread_mutex_lock(&ep->lock);
			TAILQ_REMOVE(&econn->pending, &(tx->evt), entry);
			pthread_mutex_unlock(&ep->lock);
		}
		free(iov);
		e2e_put_tx(tx);
		goto out;
	}

out:
	CCI_EXIT;
	return ret;
}

static int ctp_e2e_rma_register(cci_endpoint_t * endpoint,
				 void *start, uint64_t length,
				 int flags, cci_rma_handle_t ** rma_handle)
{
	int ret = 0;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	e2e_ep_t *eep = ep->priv;

	CCI_ENTER;

	ret = cci_rma_register(eep->real, start, length, flags, rma_handle);

	CCI_EXIT;
	return ret;
}

static int ctp_e2e_rma_deregister(cci_endpoint_t * endpoint, cci_rma_handle_t * rma_handle)
{
	int ret = 0;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	e2e_ep_t *eep = ep->priv;

	CCI_ENTER;

	ret = cci_rma_deregister(eep->real, rma_handle);

	CCI_EXIT;
	return ret;
}

static int ctp_e2e_rma(cci_connection_t * connection,
			const void *msg_ptr, uint32_t msg_len,
			cci_rma_handle_t * local_handle, uint64_t local_offset,
			cci_rma_handle_t * remote_handle, uint64_t remote_offset,
			uint64_t data_len, const void *context, int flags)
{
	int ret = 0, i = 0;
	cci__conn_t *conn = container_of(connection, cci__conn_t, connection);
	e2e_conn_t *econn = conn->priv;
	cci__ep_t *ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	e2e_rma_t *rma = NULL;
	cci_e2e_hdr_t *hdr = NULL;
	cci_e2e_rma_request_t *req = NULL;
	int len = sizeof(*hdr) + sizeof(*req);
	char buf[len];

	CCI_ENTER;

	if (!eglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	memset(buf, 0, len);

	rma = calloc(1, sizeof(*rma));
	if (!rma) {
		ret = CCI_ENOMEM;
		goto out;
	}

	rma->evt.event.type = CCI_EVENT_SEND;
	rma->evt.event.send.status = CCI_SUCCESS; /* for now */
	rma->evt.event.send.connection = connection;
	rma->evt.event.send.context = (void *)context;

	rma->evt.ep = ep;
	rma->evt.conn = conn;

	rma->lh = local_handle;
	rma->loffset = local_offset;
	rma->rh = remote_handle;
	rma->roffset = remote_offset;
	rma->length = data_len;
	rma->context = (void*)context;
	rma->flags = flags;

	if (msg_ptr && msg_len) {
		rma->msg_ptr = calloc(1, msg_len);
		if (!rma->msg_ptr) {
			ret = CCI_ENOMEM;
			goto out;
		}
		memcpy((void*)rma->msg_ptr, msg_ptr, msg_len);
		rma->msg_len = msg_len;
	}

	rma->num_frags = data_len / econn->rma_mtu;
	if (data_len != rma->num_frags * econn->rma_mtu)
		rma->num_frags++;
	rma->acked = -1;

	for (i = 0; i < (int) rma->num_frags; i++) {
		e2e_rma_frag_t *frag = NULL;

		frag = e2e_get_rma_frag(ep);
		if (!frag) {
			if (i == 0) {
				/* We were not able to launch a single fragment,
				 * bail and cleanup.
				 */
				ret = CCI_EAGAIN;
				goto out;
			}
		}

		frag->loffset = i * econn->rma_mtu;
		frag->roffset = i * econn->rma_mtu;
		frag->len = econn->rma_mtu;
		if (frag->loffset + frag->len > data_len) {
			frag->len = data_len - frag->loffset;
		}
		frag->rma = rma;
		frag->id = i;

		cci_e2e_pack_rma_request(hdr, local_handle, remote_handle,
				frag->loffset, frag->roffset, frag->len, 0, 0,
				flags & CCI_FLAG_WRITE ? CCI_E2E_MSG_RMA_WRITE_REQ :
				CCI_E2E_MSG_RMA_READ_REQ);

		ret = cci_send(econn->real, buf, len, frag, 0);
		if (ret) {
			e2e_put_rma_frag(frag);

			if (i == 0) {
				/* We were unable to send a single fragment,
				 * bail and cleanup.
				 */
				ret = CCI_EAGAIN;
			} else {
				ret = 0;
			}
			goto out;
		}

		/* We sent the frag, increment next */
		rma->next++;
	}

    out:
	if (ret) {
		if (rma) {
			free((void*)msg_ptr);
		}
		free(rma);
	}

	CCI_EXIT;
	return ret;
}
