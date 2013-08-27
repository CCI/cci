/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/private_config.h"

#include <stdio.h>
#include <sys/types.h>

#include "cci.h"
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

	/* determine is device contains as, subnet, and at least one router */
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
	TAILQ_INIT(&eep->conns);
	TAILQ_INIT(&eep->active);
	TAILQ_INIT(&eep->passive);
	TAILQ_INIT(&eep->closing);
	*((char ***)&eep->routers) = routers;
	eep->as = as;
	eep->subnet = subnet;

	pthread_mutex_lock(&dev_e2e->lock);
	TAILQ_INSERT_TAIL(&dev_e2e->eps, ep_e2e, entry);
	pthread_mutex_unlock(&dev_e2e->lock);

	*endpointp = &ep_e2e->endpoint;

    out:
	if (ret) {
		if (ep_e2e) {
			free(ep_e2e->uri);
			free(ep_e2e->priv);
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

	free(ep->priv);
	free(ep->uri);
	free(ep);

	CCI_EXIT;
	return ret;
}

static int ctp_e2e_accept(cci_event_t *event, const void *context)
{
	CCI_ENTER;

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
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
	econn->state = E2E_CONN_ACTIVE;

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
		snprintf(local_uri, prefix_len, "%s", ep_real->uri);
		snprintf(local_uri + prefix_len, base_len, "%s", base);

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
handle_native_connect(cci__ep_t *ep, cci_event_t *native_event, cci_event_t **new)
{
	int ret = 0;
	cci__conn_t *conn = native_event->connect.context;
	e2e_conn_t *econn = conn->priv;
	e2e_ep_t *eep = ep->priv;

	if (native_event->connect.status == CCI_SUCCESS) {
		econn->real = native_event->connect.connection;
	} else {
		cci__evt_t *tmp = calloc(1, sizeof(*tmp));
		if (!tmp) {
			/* FIXME */
			return CCI_EAGAIN;
		}
		tmp->event.connect.type = CCI_EVENT_CONNECT;
		tmp->event.connect.status = native_event->connect.status;
		tmp->event.connect.context = conn->connection.context;
		tmp->event.connect.connection = NULL;
		tmp->ep = ep;
		tmp->conn = NULL;
		*new = &tmp->event;
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

static int ctp_e2e_get_event(cci_endpoint_t * endpoint,
			      cci_event_t ** event)
{
	int ret = 0;
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

		switch (native_event->type) {
		case CCI_EVENT_CONNECT:
			ret = handle_native_connect(ep, native_event, event);
			break;
		case CCI_EVENT_CONNECT_REQUEST:
			break;
		case CCI_EVENT_ACCEPT:
			break;
		case CCI_EVENT_SEND:
			break;
		case CCI_EVENT_RECV:
			break;
		default:
			break;
		}
		cci_return_event(native_event);
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
		if (event->connect.status != CCI_SUCCESS) {
			cci__evt_t *evt = container_of(event, cci__evt_t, event);

			/* This was alloced in get_event().
			 * Free it now */
			free(evt);
		}
		break;
	}
	default:
		break;
	}

	CCI_EXIT;
	return ret;
}

static int ctp_e2e_send(cci_connection_t * connection,
			 const void *msg_ptr, uint32_t msg_len,
			 const void *context, int flags)
{
	CCI_ENTER;

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_sendv(cci_connection_t * connection,
			  const struct iovec *data, uint32_t iovcnt,
			  const void *context, int flags)
{
	CCI_ENTER;

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_rma_register(cci_endpoint_t * endpoint,
				 void *start, uint64_t length,
				 int flags, cci_rma_handle_t ** rma_handle)
{
	CCI_ENTER;

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_rma_deregister(cci_endpoint_t * endpoint, cci_rma_handle_t * rma_handle)
{
	CCI_ENTER;

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_e2e_rma(cci_connection_t * connection,
			const void *msg_ptr, uint32_t msg_len,
			cci_rma_handle_t * local_handle, uint64_t local_offset,
			cci_rma_handle_t * remote_handle, uint64_t remote_offset,
			uint64_t data_len, const void *context, int flags)
{
	CCI_ENTER;

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}
