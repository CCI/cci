/*
 * Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
 * $COPYRIGHT$
 */

#define _GNU_SOURCE
#include "cci/private_config.h"

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <search.h>
#include <assert.h>
#include <sys/select.h>

#include "cci.h"
#include "plugins/ctp/ctp.h"
#include "ctp_sm.h"
#include "sm_atomics.h"

sm_globals_t *smglobals = NULL;

/*
 * Local functions
 */
static int ctp_sm_init(cci_plugin_ctp_t * plugin, uint32_t abi_ver, uint32_t flags, uint32_t * caps);
static int ctp_sm_finalize(cci_plugin_ctp_t * plugin);
static const char *ctp_sm_strerror(cci_endpoint_t * endpoint, enum cci_status status);
static int ctp_sm_create_endpoint(cci_device_t * device,
				    int flags,
				    cci_endpoint_t ** endpointp,
				    cci_os_handle_t * fd);
static int ctp_sm_destroy_endpoint(cci_endpoint_t * endpoint);
static int ctp_sm_accept(cci_event_t *event, const void *context);
static int ctp_sm_reject(cci_event_t *event);
static int ctp_sm_connect(cci_endpoint_t * endpoint, const char *server_uri,
			    const void *data_ptr, uint32_t data_len,
			    cci_conn_attribute_t attribute,
			    const void *context, int flags, const struct timeval *timeout);
static int ctp_sm_disconnect(cci_connection_t * connection);
static int ctp_sm_set_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, const void *val);
static int ctp_sm_get_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, void *val);
static int ctp_sm_arm_os_handle(cci_endpoint_t * endpoint, int flags);
static int ctp_sm_get_event(cci_endpoint_t * endpoint,
			      cci_event_t ** event);
static int ctp_sm_return_event(cci_event_t * event);
static int ctp_sm_send(cci_connection_t * connection,
			 const void *msg_ptr, uint32_t msg_len,
			 const void *context, int flags);
static int ctp_sm_sendv(cci_connection_t * connection,
			  const struct iovec *data, uint32_t iovcnt,
			  const void *context, int flags);
static int ctp_sm_rma_register(cci_endpoint_t * endpoint,
				 void *start, uint64_t length,
				 int flags, cci_rma_handle_t ** rma_handle);
static int ctp_sm_rma_deregister(cci_endpoint_t * endpoint, cci_rma_handle_t * rma_handle);
static int ctp_sm_rma(cci_connection_t * connection,
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
cci_plugin_ctp_t cci_ctp_sm_plugin = {
	{
	 /* Logistics */
	 CCI_ABI_VERSION,
	 CCI_CTP_API_VERSION,
	 "sm",
	 CCI_MAJOR_VERSION, CCI_MINOR_VERSION, CCI_RELEASE_VERSION,
	 20, /* less than sock and tcp */

	 /* Bootstrap function pointers */
	 cci_ctp_sm_post_load,
	 cci_ctp_sm_pre_unload,
	 },

	/* API function pointers */
	ctp_sm_init,
	ctp_sm_finalize,
	ctp_sm_strerror,
	ctp_sm_create_endpoint,
	ctp_sm_destroy_endpoint,
	ctp_sm_accept,
	ctp_sm_reject,
	ctp_sm_connect,
	ctp_sm_disconnect,
	ctp_sm_set_opt,
	ctp_sm_get_opt,
	ctp_sm_arm_os_handle,
	ctp_sm_get_event,
	ctp_sm_return_event,
	ctp_sm_send,
	ctp_sm_sendv,
	ctp_sm_rma_register,
	ctp_sm_rma_deregister,
	ctp_sm_rma
};

static int
sm_check_path(const char *path)
{
	int ret = 0;
	struct stat stat_buf;

	/* Does the path already exist? */
	ret = stat(path, &stat_buf);
	if (ret) {
		if (errno == ENOENT) {
			ret = errno;
		} else {
			/* No, but we got another error.
			 * Report it and bail.
			 */
			debug(CCI_DB_WARN, "%s: stat(%s) failed with %s",
					__func__, path,
					strerror(errno));
			ret = CCI_ERROR;
			goto out;
		}
	} else {
		/* Yes, is it a directory and can we read/write? */
		if (!(stat_buf.st_mode & S_IFDIR)) {
			debug(CCI_DB_WARN, "%s: %s is not a directory",
					__func__, path);
			ret = CCI_ERROR;
			goto out;
		}
		if (!(stat_buf.st_mode & S_IRUSR)) {
			debug(CCI_DB_WARN, "%s: %s is not readable",
					__func__, path);
			ret = CCI_ERROR;
			goto out;
		}
		if (!(stat_buf.st_mode & S_IWUSR)) {
			debug(CCI_DB_WARN, "%s: %s is not writable",
					__func__, path);
			ret = CCI_ERROR;
			goto out;
		}
		if (!(stat_buf.st_mode & S_IXUSR)) {
			debug(CCI_DB_WARN, "%s: %s is not searchable",
					__func__, path);
			ret = CCI_ERROR;
			goto out;
		}
	}
    out:

	return ret;
}

static int
sm_create_path(const char *path)
{
	int ret = 0, len = 0;
	char *tmp = NULL, *dir = NULL, *new = NULL, *orig = NULL;

	if (!path || (len = strlen(path)) == 0)
		return CCI_EINVAL;

	orig = tmp = strdup(path);
	new = calloc(1, len + 2); /* one for trailing / and one for NULL */
	if (!tmp || !new) {
		ret = CCI_ENOMEM;
		goto out;
	}

	if (path[0] == '/') {
		new[0] = '/';
		tmp++;
	}

	while ((dir = strsep(((char **)&tmp), "/"))) {
		int dir_len = strlen(dir);

		if (!dir_len)
			continue;

		strcat(new, dir);

		/* Does the path already exist? */
		ret = sm_check_path(new);
		if (ret) {
			if (errno == ENOENT) {
				/* No, try to create it */
				ret = mkdir(new, 0755);
				if (ret) {
					debug(CCI_DB_WARN, "%s: mkdir(%s) failed with %s",
							__func__, new,
							strerror(errno));
					ret = CCI_ERROR;
					goto out;
				}
			} else {
				/* No, but we got another error.
				 * Report it and bail.
				 */
				debug(CCI_DB_WARN, "%s: stat(%s) failed with %s",
						__func__, new,
						strerror(errno));
				ret = CCI_ERROR;
				goto out;
			}
		}
		strcat(new, "/");
	}

    out:
	free(orig);
	free(new);

	return ret;
}

static int ctp_sm_init(cci_plugin_ctp_t *plugin, uint32_t abi_ver, uint32_t flags, uint32_t * caps)
{
	int ret = CCI_SUCCESS;
	cci__dev_t *dev, *ndev;
	cci_device_t **devices = NULL;
	struct cci_device *device = NULL;
	sm_dev_t *sdev = NULL;
	char dname[MAXPATHLEN];
	pid_t pid;

	CCI_ENTER;

	pid = getpid();

	smglobals = calloc(1, sizeof(*smglobals));
	if (!smglobals) {
		ret = CCI_ENOMEM;
		goto out;
	}

	devices = calloc(CCI_MAX_DEVICES, sizeof(*smglobals->devices));
	if (!devices) {
		ret = CCI_ENOMEM;
		goto out;
	}

	if (!globals->configfile) {
		char name[16];

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
		sdev = dev->priv;

		cci__init_dev(dev);
		dev->plugin = plugin;
		dev->priority = plugin->base.priority;

		device = &dev->device;
		device->transport = strdup("sm");
		memset(name, 0, sizeof(name));
		sprintf(name, "sm%d", pid);
		device->name = strdup(name);

		memset(dname, 0, sizeof(dname));
		snprintf(dname, sizeof(dname), "%s/%u", SM_DEFAULT_PATH, pid);
		sdev->path = strdup(dname);
		if (!sdev->path) {
			ret = CCI_ENOMEM;
			goto out;
		}

		ret = sm_create_path(sdev->path);
		if (ret)
			goto out;

		sdev->id = 0;

		device->up = 1;
		device->rate = UINT64_C(64000000000);
		device->pci.domain = -1;	/* per CCI spec */
		device->pci.bus = -1;		/* per CCI spec */
		device->pci.dev = -1;		/* per CCI spec */
		device->pci.func = -1;		/* per CCI spec */

		device->max_send_size = SM_DEFAULT_MSS;

		debug(CCI_DB_INFO, "%s: device %s path is %s", __func__,
			device->name, sdev->path);
		debug(CCI_DB_INFO, "%s: device %s base id is %u",
			__func__, device->name, sdev->id);
		debug(CCI_DB_INFO, "%s: device %s max_send_size is %u",
			__func__, device->name, device->max_send_size);

		cci__add_dev(dev);
		devices[smglobals->count++] = device;
	} else {
		/* find devices that we own */
		TAILQ_FOREACH_SAFE(dev, &globals->configfile_devs, entry, ndev) {
		if (0 == strcmp("sm", dev->device.transport)) {
			const char * const *arg;
			const char *path = NULL;
			char cwd[MAXPATHLEN];

			dev->plugin = plugin;
			if (dev->priority == -1)
				dev->priority = plugin->base.priority;
			device = &dev->device;

			dev->priv = calloc(1, sizeof(*sdev));
			if (!dev->priv) {
				ret = CCI_ENOMEM;
				goto out;
			}
			sdev = dev->priv;

			sdev->ids = calloc(SM_NUM_BLOCKS, sizeof(*sdev->ids));
			if (!sdev->ids) {
				ret = CCI_ENOMEM;
				goto out;
			}
			sdev->ids[0] = ~((uint64_t)0);
			sdev->num_blocks = 1;

			device->up = 1;
			device->rate = UINT64_C(64000000000);
			device->pci.domain = -1;	/* per CCI spec */
			device->pci.bus = -1;		/* per CCI spec */
			device->pci.dev = -1;		/* per CCI spec */
			device->pci.func = -1;		/* per CCI spec */

			/* parse conf_argv */
			for (arg = device->conf_argv; *arg != NULL; arg++) {
				if (0 == strncmp("path=", *arg, 5)) {
					char *c = NULL;

					path = *arg + 5;

					if (sdev->path) {
						debug(CCI_DB_WARN,
							"%s: device %s already "
							"has a path %s and the "
							"configfile also has %s",
							__func__, device->name,
							sdev->path, path);
						ret = CCI_EINVAL;
						goto out;
					}
					if (path[0] != '/') {
						struct sockaddr_un sun;

						debug(CCI_DB_INFO, "%s: converting "
							"relative path to absolute "
							"path", __func__);

						c = getcwd(cwd, sizeof(cwd));
						if (!c) {
							debug(CCI_DB_WARN, "%s: getcwd() "
								" failed with %s", __func__,
								strerror(errno));
							ret = CCI_ERROR;
							goto out;
						}
						if ((strlen(c) + strlen(path) + 2) >
							(sizeof(sun.sun_path) - 6)) {
							debug(CCI_DB_WARN, "%s: the path "
								"%s/%s is too long", __func__,
								c, path);
							ret = CCI_ERROR;
							goto out;
						}
						strcat(cwd, "/");
						strcat(cwd, path);
						path = cwd;
					}
				} else if (0 == strncmp("pid=", *arg, 4)) {
					const char *pid_str = *arg + 4;

					uint32_t new_pid = strtoul(pid_str, NULL, 0);
					if (sdev->pid) {
						debug(CCI_DB_WARN,
							"%s: device %s already "
							"has an pid %u and the "
							"configfile also has %u",
							__func__, device->name,
							sdev->pid, new_pid);
						ret = CCI_EINVAL;
						goto out;
					}
					sdev->pid = new_pid;
				} else if (0 == strncmp("id=", *arg, 3)) {
					const char *id_str = *arg + 3;
					uint32_t id = strtoul(id_str, NULL, 0);
					if (sdev->id) {
						debug(CCI_DB_WARN,
							"%s: device %s already "
							"has an id %u and the "
							"configfile also has %u",
							__func__, device->name,
							sdev->id, id);
						ret = CCI_EINVAL;
						goto out;
					}
					sdev->id = id;
				} else if (0 == strncmp("mss=", *arg, 4)) {
					const char *mss_str = *arg + 4;
					uint32_t mss = strtoul(mss_str, NULL, 0);
					if (device->max_send_size) {
						debug(CCI_DB_WARN,
							"%s: device %s already "
							"has a max_send_size %u "
							"and the configfile also "
							"has %u", __func__,
							device->name,
							device->max_send_size, mss);
						ret = CCI_EINVAL;
						goto out;
					}
					if (mss & (mss - 1)) {
						debug(CCI_DB_WARN,
							"%s: configfile has mss="
							"%u which is not a power "
							"of two.", __func__, mss);
					}
					device->max_send_size = mss;
				}
			}

			if (!sdev->pid)
				sdev->pid = pid;

			if (!path)
				path = SM_DEFAULT_PATH;

			memset(dname, 0, sizeof(dname));
			snprintf(dname, sizeof(dname), "%s/%u", path, sdev->pid);
			sdev->path = strdup(dname);
			if (!sdev->path) {
				ret = CCI_ENOMEM;
				goto out;
			}

			ret = sm_create_path(sdev->path);
			if (ret)
				goto out;


			if (device->max_send_size == 0)
				device->max_send_size = SM_DEFAULT_MSS;

			debug(CCI_DB_INFO, "%s: device %s path is %s", __func__,
				device->name, sdev->path);
			debug(CCI_DB_INFO, "%s: device %s base id is %u",
				__func__, device->name, sdev->id);
			debug(CCI_DB_INFO, "%s: device %s max_send_size is %u",
				__func__, device->name, device->max_send_size);

			/* queue to the main device list now */
			TAILQ_REMOVE(&globals->configfile_devs, dev, entry);
			cci__add_dev(dev);
			devices[smglobals->count++] = device;
		}
		}
	}

	devices =
		realloc(devices, (smglobals->count + 1) * sizeof(cci_device_t *));
	devices[smglobals->count] = NULL;

	*((cci_device_t ***)&smglobals->devices) = devices;

out:
	if (ret) {
		if (devices) {
			int i = 0;
			cci_device_t *device = NULL;
			cci__dev_t *dev = NULL;

			while (devices[i] != NULL) {
				device = devices[i];
				dev = container_of(device, cci__dev_t, device);
				if (dev->priv) {
					sm_dev_t *sdev = dev->priv;

					rmdir(sdev->path);
					free(sdev->path);
					free(sdev->ids);
					free(sdev);
				}
			}
		}
		free((void*)devices);

		if (smglobals) {
			free(smglobals);
			smglobals = NULL;
		}
	}
	CCI_EXIT;
	return ret;
}

static int ctp_sm_finalize(cci_plugin_ctp_t * plugin)
{
	cci__dev_t *dev = NULL;

	CCI_ENTER;

	if (!smglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	TAILQ_FOREACH(dev, &globals->devs, entry) {
		if (!strcmp(dev->device.transport, "sm")) {
			if (dev->priv) {
				sm_dev_t *sdev = dev->priv;

				rmdir(sdev->path);
				free(sdev->path);
				free(sdev->ids);
			}
			free(dev->priv);
			dev->priv = NULL;
		}
	}

	free(smglobals->devices);
	free((void*)smglobals);
	smglobals = NULL;

	CCI_EXIT;
	return CCI_SUCCESS;
}

static const char *ctp_sm_strerror(cci_endpoint_t * endpoint, enum cci_status status)
{
	return strerror(status);
}

/* Get the first available endpoint id.
 * Available ids are not set; used ids are set.
 * If none are available, allocate a new block.
 */
static int
sm_get_ep_id(cci__dev_t *dev, uint32_t *id)
{
	int ret = CCI_SUCCESS, i = 0, found = 0;
	uint32_t shift = 0;
	uint64_t *b = NULL;
	sm_dev_t *sdev = dev->priv;

	pthread_mutex_lock(&dev->lock);
	for (i = 0; i < (int) sdev->num_blocks; i++) {
		b = &sdev->ids[i];
		if (*b) {
			shift = (uint32_t) ffsl(*b);
			assert(shift);	/* it must find a bit */
			shift--;
			assert((*b & ((uint64_t)1 << shift)) == 1);
			*b = *b & ~(((uint64_t)1) << shift);
			found = 1;
			break;
		}
	}
	if (!found) {
		uint64_t *new = NULL;

		/* allocate a new block */
		sdev->num_blocks++;
		new = realloc(sdev->ids, sdev->num_blocks * sizeof(*sdev->ids));
		if (!new) {
			ret = CCI_ENOMEM;
			sdev->num_blocks--;
			goto out;
		}
		sdev->ids = new;
		shift = 0;
		b = &sdev->ids[sdev->num_blocks - 1];
		*b = ~((uint64_t)1);
	}
out:
	pthread_mutex_unlock(&dev->lock);

	if (!ret)
		*id = (i * 64) + shift + sdev->id; /* block + offset + base id */

	return ret;
}

static int
sm_put_ep_id(cci__dev_t *dev, uint32_t id)
{
	int ret = CCI_SUCCESS, i = 0;
	uint32_t shift = 0;
	uint64_t *b = NULL;
	sm_dev_t *sdev = dev->priv;

	/* Subtract the base id */
	id -= sdev->id;

	/* Determine which block */
	i = id / SM_BLOCK_SIZE;

	/* determine the shift */
	shift = (id & (SM_BLOCK_SIZE - 1));

	pthread_mutex_lock(&dev->lock);
	b = &sdev->ids[i];
	assert((*b & ((uintptr_t)1 << shift)) == 0);
	*b |= (uint64_t)1 << shift;
	pthread_mutex_unlock(&dev->lock);

	return ret;
}

static inline int
check_block(uint64_t block, int cnt, int shift, int *offset)
{
	int ret = 0, i = 0;
	uint64_t bits = ((uint64_t)1 << cnt) - 1;

	if (cnt < 1)
		return EINVAL;

	if (cnt + *offset >= 64)
		return EAGAIN;

	bits = bits << *offset;

	if ((block & bits) == bits) {
		goto out;
	} else if (!shift) {
		goto failed;
	}

	for (i = *offset + 1; i <= (64 - cnt); i++) {
		bits = bits << 1;
		if ((block & bits) == bits) {
			if (offset)
				*offset = i;
			goto out;
		}
	}
    failed:
	ret = EAGAIN;
    out:
	return ret;
}

static int
sm_compare_conns(const void *pa, const void *pb)
{
	const sm_conn_t *a = pa, *b = pb;

	if (a->id < b->id)
		return -1;
	if (a->id > b->id)
		return 1;
	return 0;
}

static int
sm_progress_sock(cci__ep_t *ep);

static void *
sm_conn_thread(void *arg)
{
	int ret = 0;
	cci__ep_t *ep = arg;
	sm_ep_t *sep = ep->priv;
	struct timeval tv = { 1, 0 };
	socklen_t slen = sizeof(tv);

	ret = setsockopt(sep->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, slen);
	if (ret)
		debug(CCI_DB_CONN, "%s: setsockopt() failed with %s", __func__,
				strerror(errno));

	while (!ep->closing)
		sm_progress_sock(ep);

	pthread_exit(NULL);
}

static int ctp_sm_create_endpoint(cci_device_t * device,
				    int flags,
				    cci_endpoint_t ** endpointp,
				    cci_os_handle_t * fd)
{
	int ret = CCI_SUCCESS;
	uint32_t id = 0;
	struct cci_endpoint *endpoint = (struct cci_endpoint *) *endpointp;
	cci__dev_t *dev = NULL;
	cci__ep_t *ep = NULL;
	sm_dev_t *sdev = NULL;
	sm_ep_t *sep = NULL;
	struct sockaddr_un sun;
	char name[MAXPATHLEN]; /* max UNIX domain socket name */
	char uri[MAXPATHLEN]; /* sm:// + name */

	CCI_ENTER;

	if (!smglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	/* TODO support blocking mode
	 * in the meantime, fail if the fd is requested */
	if (fd) {
		debug(CCI_DB_WARN, "%s: The SM transport does not yet "
			"support blocking mode via the OS handle. "
			"Either choose another transport or set the "
			"OS handle to NULL\n", __func__);
		CCI_EXIT;
		return CCI_ERR_NOT_IMPLEMENTED;
	}

	dev = container_of(device, cci__dev_t, device);
	if (0 != strcmp("sm", device->transport)) {
		CCI_EXIT;
		return CCI_EINVAL;
	}
	sdev = dev->priv;

	ep = container_of(endpoint, cci__ep_t, endpoint);
	ep->priv = calloc(1, sizeof(*sep));
	if (!ep->priv) {
		CCI_EXIT;
		return CCI_ENOMEM;
	}

	ep->rx_buf_cnt = SM_EP_RX_CNT;
	ep->tx_buf_cnt = SM_EP_TX_CNT;
	ep->buffer_len = dev->device.max_send_size;
	ep->tx_timeout = 0;

	sep = ep->priv;

	ret = pthread_rwlock_init(&sep->conns_lock, NULL);
	if (ret) {
		goto out;
	}

	TAILQ_INIT(&sep->active);
	TAILQ_INIT(&sep->passive);
	TAILQ_INIT(&sep->closing);

	ret = sm_get_ep_id(dev, &id);
	if (ret) goto out;

	sep->id = id;

	/* If the path length plus enough room for a uint32_t and NULL
	 * exceeds the sizeof name (sun.sun_path) length, bail */
	if ((strlen(sdev->path) + 12) > sizeof(name)) {
		ret = CCI_EINVAL;
		goto out;
	}

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s/%u", sdev->path, sep->id);

	memset(uri, 0, sizeof(uri));
	snprintf(uri, sizeof(uri), "sm://%s", name);
	ep->uri = strdup(uri);
	if (!ep->uri) {
		ret = CCI_ENOMEM;
		goto out;
	}

	ret = sm_create_path(name);
	if (ret)
		goto out;

	/* store the directory name in uri */
	memset(uri, 0, sizeof(uri));
	snprintf(uri, sizeof(uri), "%s", name);

	/* Create conns sub-directory */

	/* If there is not enough space to append "/conns", bail */
	if (strlen(uri) >= (sizeof(name) - 7)) {
		ret = CCI_EINVAL;
		goto out;
	}

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s/conns", uri);

	ret = sm_create_path(name);
	if (ret)
		goto out;

	/* Create FIFO for receiving keepalives and wakeups */

	/* If there is not enough space to append "/fifo", bail */
	if (strlen(uri) >= (sizeof(name) - 6)) {
		ret = CCI_EINVAL;
		goto out;
	}

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s/fifo", uri);

	unlink(name);
	ret = mkfifo(name, 0622);
	if (ret) {
		debug(CCI_DB_WARN, "%s: mkfifo(%s) failed with %s", __func__,
				name, strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}

	ret = open(name, O_RDWR|O_NONBLOCK);
	if (ret == -1) {
		debug(CCI_DB_WARN, "%s: open(%s) failed with %s", __func__,
				name, strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}
	sep->fifo = ret;

	sep->conn_ids = malloc(SM_EP_MAX_CONNS / sizeof(*sep->conn_ids));
	if (!sep->conn_ids) {
		ret = CCI_ENOMEM;
		goto out;
	}
	memset(sep->conn_ids, 0xFF, SM_EP_MAX_CONNS / sizeof(*sep->conn_ids));

	/* Create listening socket for connection setup */

	/* If there is not enough space to append "/sock", bail */
	if (strlen(uri) >= (sizeof(name) - 6)) {
		ret = CCI_EINVAL;
		goto out;
	}

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s/sock", uri);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path, name, strlen(name));

	ret = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (ret == -1) {
		debug(CCI_DB_WARN, "%s: socket() failed with %s", __func__,
				strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}
	sep->sock = ret;

	ret = bind(sep->sock, (const struct sockaddr *)&sun, sizeof(sun));
	if (ret) {
		debug(CCI_DB_WARN, "%s: bind() failed with %s", __func__,
				strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}

	ret = pthread_create(&sep->conn_tid, NULL, sm_conn_thread, (void *)ep);

out:
	if (ret)
		ctp_sm_destroy_endpoint(endpoint);

	CCI_EXIT;
	return ret;
}

static int ctp_sm_destroy_endpoint(cci_endpoint_t * endpoint)
{
	int ret = 0;
	cci__dev_t *dev = NULL;
	cci__ep_t *ep = NULL;
	sm_ep_t *sep = NULL;
	char *path = NULL;

	CCI_ENTER;

	if (!endpoint) {
		ret = CCI_EINVAL;
		goto out;
	}

	ep = container_of(endpoint, cci__ep_t, endpoint);
	dev = ep->dev;
	sep = ep->priv;

	if (ep->uri)
		path = (void*)((uintptr_t)ep->uri + strlen("sm://"));

	if (sep) {
		char name[MAXPATHLEN];

		if (sep->sock) {
			close(sep->sock);
			memset(name, 0, sizeof(name));
			snprintf(name, sizeof(name), "%s/sock", path);
			unlink(name);
		}

		/* TODO: Close all open connections */

		free(sep->conn_ids);

		/* Close FIFO */
		if (sep->fifo) {
			close(sep->fifo);
			memset(name, 0, sizeof(name));
			snprintf(name, sizeof(name), "%s/fifo", path);
			unlink(name);
		}

		sm_put_ep_id(dev, sep->id);
		free(sep);
		ep->priv = NULL;
	}

	if (ep->uri) {
		rmdir(path);
		free((char *)ep->uri);
		ep->uri = NULL;
	}

    out:
	CCI_EXIT;
	return ret;
}

#define ID_SHIFT	(6)
#define ID_MASK		((1 << ID_SHIFT) - 1)

static int
sm_get_conn_id(sm_conn_t *sconn)
{
	int ret = CCI_EAGAIN;
	cci__conn_t *conn = sconn->conn;
	cci_connection_t *connection = &conn->connection;
	cci__ep_t *ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	sm_ep_t *sep = ep->priv;
	uint32_t block = sep->last_id >> ID_SHIFT; /* divide by 64 */
	uint32_t offset = sep->last_id & ID_MASK;
	uint32_t last = block;

	pthread_mutex_lock(&ep->lock);
	do {
		uint64_t b = sep->conn_ids[block];

		offset = ffsl(b);
		if (offset) {
			offset--;
			sep->conn_ids[block] =
				sep->conn_ids[block] & ~((uint64_t)1 << offset);
			sep->last_id = sconn->id = (block << ID_SHIFT) + offset;
			ret = 0;
			break;
		}

		block++;
		if (block == SM_EP_MAX_CONNS >> ID_SHIFT)
			block = 0;
	} while (block != last);

	pthread_mutex_unlock(&ep->lock);

	return ret;
}

static int
sm_put_conn_id(sm_conn_t *sconn)
{
	int ret = 0;
	cci__conn_t *conn = sconn->conn;
	cci_connection_t *connection = &conn->connection;
	cci__ep_t *ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	sm_ep_t *sep = ep->priv;
	uint32_t block = sconn->id >> ID_SHIFT;
	uint32_t offset = sconn->id & ID_MASK;

	pthread_mutex_lock(&ep->lock);
	sep->conn_ids[block] = sep->conn_ids[block] | ((uint64_t)1 << offset);
	pthread_mutex_unlock(&ep->lock);

	return ret;
}

static int
sm_map_conn(sm_conn_t *sconn)
{
	int ret = 0, msgs_fd = 0, len = 0;
	char name[MAXPATHLEN], *ptr = NULL;

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s", sconn->name);
	ptr = strstr(name, "/sock");
	snprintf(ptr, sizeof(name) - (ptr - name),
			"/conns/%d", sconn->peer_id);

	ret = open(name, O_RDWR, 0666);
	if (ret == -1) {
		debug(CCI_DB_CONN, "%s: unable to open %s's mmap buf", __func__,
				sconn->conn->uri);
		ret = EHOSTUNREACH;
		goto out;
	}
	msgs_fd = ret;
	ret = 0;

	len = sizeof(*sconn->rx);

	/* MMAP the buffer */
	sconn->peer_mmap = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, msgs_fd, 0);
	close(msgs_fd);
	if (sconn->peer_mmap == MAP_FAILED) {
		debug(CCI_DB_WARN, "%s: mmap() failed with %s", __func__,
				strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}
	sconn->rx = sconn->peer_mmap;
    out:
	return ret;
}

static int ctp_sm_accept(cci_event_t *event, const void *context)
{
	int ret = 0, len = 0;
	cci__evt_t *evt = NULL;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	sm_ep_t *sep = NULL;
	sm_conn_t *sconn = NULL;
	sm_conn_hdr_t hdr;
	struct sockaddr_un sun;
	socklen_t slen = sizeof(sun);

	CCI_ENTER;

	evt = container_of(event, cci__evt_t, event);
	ep = evt->ep;
	conn = evt->conn;
	sep = ep->priv;
	sconn = conn->priv;

	conn->connection.context = (void *)context;

	ret = sm_map_conn(sconn);
	if (ret)
		goto out;

	evt = calloc(1, sizeof(*evt));
	if (!evt) {
		ret = CCI_ENOMEM;
		goto out;
	}
	evt->event.type = CCI_EVENT_ACCEPT;
	evt->event.accept.status = CCI_SUCCESS;
	evt->event.accept.context = (void*)context;
	evt->event.accept.connection = &conn->connection;
	evt->ep = ep;
	evt->conn = conn;

	len = sizeof(hdr);

	memset(&hdr, 0, len);
	hdr.reply.type = SM_CMSG_CONN_REPLY;
	hdr.reply.status = CCI_SUCCESS;
	hdr.reply.server_id = sconn->peer_id;
	hdr.reply.client_id = sconn->id;

	memset(&sun, 0, slen);
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path, sconn->name, strlen(sconn->name));

	ret = sendto(sep->sock, &hdr, len, 0, (struct sockaddr*)&sun, slen);
	if (ret == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			ret = CCI_EAGAIN;
			break;
		default:
			debug(CCI_DB_CONN, "%s: sendto(%s) failed with %s",
				__func__, sconn->name, strerror(errno));
			ret = CCI_ERROR;
			break;
		}
		goto out;
	} else if (ret != len) {
		debug(CCI_DB_CONN, "%s: sendto(%s) returned only %d of expected %d bytes",
			__func__, sconn->name, ret, len);
		ret = CCI_ENOBUFS;
		goto out;
	}
	ret = 0;

	sconn->state = SM_CONN_READY;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
	pthread_mutex_unlock(&ep->lock);

    out:
	if (ret) {
		/* TODO cleanup conn or queue for retry depending on error */
	}
	CCI_EXIT;
	return ret;
}

static void
sm_free_conn(cci__conn_t *conn)
{
	int ret = 0;
	cci_connection_t *connection = &conn->connection;
	cci__ep_t *ep = container_of(connection->endpoint, cci__ep_t, endpoint);
	sm_ep_t *sep = ep->priv;
	sm_conn_t *sconn = conn->priv;

	if (sconn) {
		free(sconn->name);
		if (sconn->id != -1) {
			ret = pthread_rwlock_wrlock(&sep->conns_lock);
			if (ret) {
				debug(CCI_DB_WARN, "%s: pthread_rwlock_wrlock() "
					"failed with %s", __func__, strerror(ret));
			} else {
				void *node = NULL;

				/* We have the lock */
				node = tfind(sconn, &sep->conns, sm_compare_conns);
				if (node) {
					sm_conn_t *tmp = NULL;

					tmp = *((sm_conn_t **)node);
					if (tmp == sconn) {
						tdelete(sconn, &sep->conns,
								sm_compare_conns);
					}
				}
				pthread_rwlock_unlock(&sep->conns_lock);
			}
			sm_put_conn_id(sconn);
		}
		free(sconn);
	}
	free((void*)conn->uri);
	free(conn);

	return;
}

static int ctp_sm_reject(cci_event_t *event)
{
	int ret = 0, len = 0;
	cci__evt_t *evt = NULL;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	sm_ep_t *sep = NULL;
	sm_conn_t *sconn = NULL;
	sm_conn_hdr_t hdr;
	struct sockaddr_un sun;
	socklen_t slen = sizeof(sun);

	CCI_ENTER;

	evt = container_of(event, cci__evt_t, event);
	ep = evt->ep;
	conn = evt->conn;
	sep = ep->priv;
	sconn = conn->priv;

	len = sizeof(hdr);

	memset(&hdr, 0, len);
	hdr.reply.type = SM_CMSG_CONN_REPLY;
	hdr.reply.status = CCI_ECONNREFUSED;
	hdr.reply.server_id = sconn->peer_id;
	hdr.reply.client_id = 0;

	memset(&sun, 0, slen);
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path, sconn->name, strlen(sconn->name));

	ret = sendto(sep->sock, &hdr, len, 0, (struct sockaddr*)&sun, slen);
	if (ret == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			ret = CCI_EAGAIN;
			break;
		default:
			debug(CCI_DB_CONN, "%s: sendto(%s) failed with %s",
				__func__, sconn->name, strerror(errno));
			ret = CCI_ERROR;
			break;
		}
	} else if (ret != len) {
		debug(CCI_DB_CONN, "%s: sendto(%s) returned only %d of expected %d bytes",
			__func__, sconn->name, ret, len);
		ret = CCI_ENOBUFS;
		goto out;
	}
	ret = 0;

    out:
	sm_free_conn(conn);

	CCI_EXIT;
	return ret;
}

static int
sm_parse_uri(const char *uri, int *pidp, int *idp)
{
	int ret = 0, pid = 0, id = 0;
	char buffer[MAXPATHLEN], *ptr = NULL;

	if (memcmp(uri, "sm://", 5)) {
		ret = CCI_EINVAL;
		goto out;
	}

	memset(buffer, 0, sizeof(buffer));
	strcpy(buffer, uri);

	ptr = strrchr(buffer, '/');
	if (!ptr) {
		ret = CCI_EINVAL;
		goto out;
	}

	ptr++;
	id = strtol(ptr, NULL, 0);

	ptr--;
	*ptr = '\0';

	ptr = strrchr(buffer, '/');
	if (!ptr) {
		ret = CCI_EINVAL;
		goto out;
	}

	ptr++;
	pid = strtol(ptr, NULL, 0);

	*pidp = pid;
	*idp = id;

    out:
	return ret;
}

static int
sm_create_conn(cci__ep_t *ep, const char *uri, cci__conn_t **connp)
{
	int ret = 0, peer_pid = 0, peer_id = 0, len = 0, msgs_fd = 0, i = 0;
	cci__conn_t *conn = NULL;
	cci__dev_t *dev = ep->dev;
	sm_dev_t *sdev = dev->priv;
	sm_ep_t *sep = ep->priv;
	sm_conn_t *sconn = NULL, *tmp = NULL;
	char name[MAXPATHLEN];
	const char *path = NULL;
	void *node = NULL;
	int *id = NULL;

	CCI_ENTER;

	ret = sm_parse_uri(uri, &peer_pid, &peer_id);
	if (ret) goto out;

	conn = calloc(1, sizeof(*conn));
	sconn = calloc(1, sizeof(*sconn));
	if (!conn || !sconn) {
		ret = CCI_ENOMEM;
		goto out;
	}
	conn->priv = sconn;

	conn->plugin = ep->plugin;
	conn->connection.endpoint = &ep->endpoint;
	conn->connection.max_send_size = ep->endpoint.device->max_send_size;

	conn->uri = strdup(uri);
	if (!conn->uri) {
		ret = CCI_ENOMEM;
		goto out;
	}
	conn->tx_timeout = ep->tx_timeout;
	conn->keepalive_timeout = ep->keepalive_timeout;

	sconn->conn = conn;
	sconn->id = -1;		/* for now, to aid in cleanup */
	ret = sm_get_conn_id(sconn);
	if (ret) goto out;

	sconn->rxs = calloc(64, sizeof(*sconn->rxs));
	if (!sconn->rxs) {
		ret = CCI_ENOMEM;
		goto out;
	}

	for (i = 0; i < 64; i++) {
		cci__evt_t *evt = &sconn->rxs[i];

		evt->event.type = CCI_EVENT_RECV;
		evt->event.recv.connection = &conn->connection;
		evt->ep = ep;
		evt->conn = conn;
	}

	path = uri + 5; /* sm:// */
	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s/sock", path);
	sconn->name = strdup(name);
	if (!sconn->name) {
		ret = CCI_ENOMEM;
		goto out;
	}

	/* Can we open their FIFO? */
	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s/fifo", path);
	ret = open(name, O_WRONLY|O_NONBLOCK);
	if (ret == -1) {
		debug(CCI_DB_CONN, "%s: unable to open %s's FIFO", __func__, uri);
		ret = EHOSTUNREACH;
	}
	sconn->fifo = ret;

	/* Open our shared memory object */
	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s/%u/conns/%d", sdev->path, sep->id, sconn->id);
	ret = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (ret == -1) {
		debug(CCI_DB_CONN, "%s: unable to open %s's mmap buf", __func__, uri);
		ret = EHOSTUNREACH;
		goto out;
	}
	msgs_fd = ret;

	len = sizeof(*sconn->tx);

	ret = ftruncate(msgs_fd, len);
	if (ret) {
		debug(CCI_DB_WARN, "%s: ftruncate(%s, %d) failed with %s", __func__,
				name, len, strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}

	/* MMAP the buffer */
	sconn->mmap = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, msgs_fd, 0);
	close(msgs_fd);
	if (sconn->mmap == MAP_FAILED) {
		debug(CCI_DB_WARN, "%s: mmap() failed with %s", __func__,
				strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}

	sconn->tx = sconn->mmap;
	/* We can just set this and rely on ring_init() to call
	 * a memory barrier.
	 */
	sconn->tx->avail = ~(0ULL);
	ring_init(&(sconn->tx->ring), 64); /* magic number */

	/* Add new conn to the conns tree */
	ret = pthread_rwlock_wrlock(&sep->conns_lock);
	if (ret) {
		debug(CCI_DB_WARN, "%s: pthread_rwlock_wrlock() failed with %s",
				__func__, strerror(ret));
		goto out;
	}

	node = tfind(sconn, &sep->conns, sm_compare_conns);
	if (node) {
		pthread_rwlock_unlock(&sep->conns_lock);
		debug(CCI_DB_WARN, "%s: id %d already exists for conn %p (%s)",
				__func__, *id, (void*)tmp, tmp->name);
		ret = CCI_ERROR;
		goto out;
	}

	node = tsearch(sconn, &sep->conns, sm_compare_conns);
	if (!node) {
		pthread_rwlock_unlock(&sep->conns_lock);
		ret = CCI_ENOMEM;
		goto out;
	}

	/* No need to check the return here - it can only fail with EINVAL if
	 * the lock is invalid or EPERM if we do not hold it.
	 */
	pthread_rwlock_unlock(&sep->conns_lock);

	*connp = conn;

    out:
	if (ret) {
		if (sconn) {
			if (sconn->mmap)
				munmap(sconn->mmap, len);
			if (sconn->fifo)
				close(sconn->fifo);
			free(sconn->name);
			sm_put_conn_id(sconn);
			free(sconn);
		}
		if (conn) {
			free((char*)conn->uri);
			free(conn);
		}
	}
	return ret;
}

static int ctp_sm_connect(cci_endpoint_t * endpoint, const char *server_uri,
			    const void *data_ptr, uint32_t data_len,
			    cci_conn_attribute_t attribute,
			    const void *context, int flags, const struct timeval *timeout)
{
	int ret = 0;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	cci__conn_t *conn = NULL;
	sm_ep_t *sep = ep->priv;
	sm_conn_t *sconn = NULL;
	sm_conn_params_t *params = NULL;
	sm_conn_hdr_t hdr;
	struct sockaddr_un sun;
	struct iovec iov[2];
	struct msghdr msg;

	CCI_ENTER;

	ret = sm_create_conn(ep, server_uri, &conn);
	if (ret) goto out;

	conn->connection.attribute = attribute;
	conn->connection.context = (void *)context;

	sconn = conn->priv;
	sconn->state = SM_CONN_ACTIVE;

	params = calloc(1, sizeof(*params));
	if (!params) {
		ret = CCI_ENOMEM;
		goto out;
	}
	sconn->params = params;

	if (data_ptr && data_len) {
		params->data_ptr = malloc(data_len);
		if (!params->data_ptr) {
			ret = CCI_ENOMEM;
			goto out;
		}
		memcpy(params->data_ptr, data_ptr, data_len);
		params->data_len = data_len;
	}
	params->flags = flags;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path, sconn->name, strlen(sconn->name));

	memset(&hdr, 0, sizeof(hdr));
	hdr.connect.type = SM_CMSG_CONNECT;
	hdr.connect.version = 0;
	hdr.connect.len = data_len;
	hdr.connect.server_id = sconn->id;

	memset(&iov, 0, sizeof(iov));
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = params->data_ptr;
	iov[1].iov_len = params->data_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sun;
	msg.msg_namelen = sizeof(sun);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	ret = sendmsg(sep->sock, &msg, 0);
	if (ret == -1) {
		switch (errno) {
		case ENOENT:
		case ENOTDIR:
			ret = EHOSTUNREACH;
			break;
		default:
			ret = CCI_ERROR;
		}
		goto out;
	} else if(ret != (int)(iov[0].iov_len + iov[1].iov_len)) {
		ret = CCI_ENOBUFS;
		goto out;
	} else {
		ret = 0;
	}

    out:
	if (ret) {
		if (params) {
			free(params->data_ptr);
			free(params);
		}
		sm_free_conn(conn);
	}

	CCI_EXIT;
	return ret;
}

static int ctp_sm_disconnect(cci_connection_t * connection)
{
	CCI_ENTER;

	debug(CCI_DB_INFO, "%s", "In sm_disconnect\n");

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_sm_set_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, const void *val)
{
	CCI_ENTER;

	debug(CCI_DB_INFO, "%s", "In sm_set_opt\n");

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_sm_get_opt(cci_opt_handle_t * handle,
			    cci_opt_name_t name, void *val)
{
	CCI_ENTER;

	debug(CCI_DB_INFO, "%s", "In sm_get_opt\n");

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_sm_arm_os_handle(cci_endpoint_t * endpoint, int flags)
{
	CCI_ENTER;

	debug(CCI_DB_INFO, "%s", "In sm_arm_os_handle\n");

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int
sm_handle_connect(cci__ep_t *ep, const char *path, void *buffer, int len)
{
	int ret = 0;
	cci__conn_t *conn = NULL;
	sm_conn_t *sconn = NULL;
	sm_conn_hdr_t *hdr = buffer;
	cci__evt_t *rx = NULL;
	char uri[MAXPATHLEN], *suffix = NULL;
	void *p = (void*)((uintptr_t)buffer + sizeof(*hdr));

	memset(uri, 0, sizeof(uri));
	snprintf(uri, sizeof(uri), "sm://%s", path);
	suffix = strstr(uri, "/sock");
	*suffix = '\0';

	if (hdr->connect.len != len) {
		debug(CCI_DB_CONN, "%s: recv'd %d bytes from %s, but header "
			"declares %d bytes - dropping message", __func__, len,
			uri, hdr->connect.len);
		goto out;
	}

	rx = calloc(1, sizeof(*rx));
	if (!rx) {
		ret = CCI_ENOMEM;
		goto out;
	}
	rx->event.request.type = CCI_EVENT_CONNECT_REQUEST;
	rx->ep = ep;

	if (len) {
		rx->event.request.data_len = len;
		rx->event.request.data_ptr = calloc(1, len);
		if (!rx->event.request.data_ptr) {
			ret = CCI_ENOMEM;
			goto out;
		}
		memcpy(*((void**)&rx->event.request.data_ptr), p, len);
	}

	ret = sm_create_conn(ep, uri, &conn);
	if (ret) goto out;

	rx->conn = conn;
	conn->connection.attribute = hdr->connect.attribute;

	sconn = conn->priv;
	sconn->state = SM_CONN_PASSIVE;
	sconn->peer_id = hdr->connect.server_id;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, rx, entry);
	pthread_mutex_unlock(&ep->lock);

    out:
	if (ret) {
		debug(CCI_DB_CONN, "%s: unable to service connect request from "
			"%s (%s) - dropping message", __func__, uri,
			cci_strerror(&ep->endpoint, ret));
		if (conn) {
			sm_free_conn(conn);
		}
		if (rx) {
			free((void*)rx->event.request.data_ptr);
			free(rx);
		}
	}
	return ret;
}

static int
sm_find_conn(cci__ep_t *ep, int id, cci__conn_t **connp)
{
	int ret = 0;
	sm_ep_t *sep = ep->priv;
	sm_conn_t key;
	void *node = NULL;

	CCI_ENTER;

	key.id = id;

	/* Add new conn to the conns tree */
	ret = pthread_rwlock_rdlock(&sep->conns_lock);
	if (ret) {
		debug(CCI_DB_WARN, "%s: pthread_rwlock_rdlock() failed with %s",
				__func__, strerror(ret));
		goto out;
	}

	node = tfind(&key, &sep->conns, sm_compare_conns);
	if (node) {
		sm_conn_t *sconn = *((sm_conn_t**)node);
		*connp = sconn->conn;
	} else {
		debug((CCI_DB_CONN|CCI_DB_MSG), "%s: unable to find conn with ID %d",
			__func__, id);
		ret = CCI_ERROR;
	}
	pthread_rwlock_unlock(&sep->conns_lock);

    out:
	CCI_EXIT;
	return ret;
}

static int
sm_handle_connect_reply(cci__ep_t *ep, void *buffer)
{
	int ret = 0, id = 0, len = 0;
	cci__evt_t *evt = NULL;
	cci__conn_t *conn = NULL;
	sm_ep_t *sep = ep->priv;
	sm_conn_t *sconn = NULL;
	sm_conn_hdr_t *hdr = buffer;
	sm_conn_params_t *params = NULL;
	struct sockaddr_un sun;
	socklen_t slen = sizeof(sun);

	evt = calloc(1, sizeof(*evt));
	if (!evt) {
		ret = CCI_ENOMEM;
		goto out;
	}
	evt->ep = ep;

	id = hdr->reply.server_id;

	ret = sm_find_conn(ep, id, &conn);
	if (ret) goto out;

	evt->conn = conn;

	sconn = conn->priv;
	params = sconn->params;

	free(params->data_ptr);
	free(params);

	evt->event.type = CCI_EVENT_CONNECT;
	evt->event.connect.context = conn->connection.context;

	memset(&sun, 0, slen);
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path, sconn->name, strlen(sconn->name));

	debug(CCI_DB_CONN, "%s: %s %s (status %u)", __func__, conn->uri,
			hdr->reply.status ? "rejected" : "accepted",
			hdr->reply.status);

	if (hdr->reply.status == CCI_SUCCESS) {
		sconn->peer_id = hdr->reply.client_id;
		evt->conn = conn;
		evt->event.connect.status = CCI_SUCCESS;
		evt->event.connect.connection = &conn->connection;
		sconn->state = SM_CONN_READY;
		ret = sm_map_conn(sconn);
		if (ret)
			goto out;
	} else {
		evt->event.connect.status = hdr->reply.status;
		sm_free_conn(conn);
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
	pthread_mutex_unlock(&ep->lock);

	hdr->ack.type = SM_CMSG_CONN_ACK;
	hdr->ack.pad = 0;

	len = sizeof(*hdr);

	ret = sendto(sep->sock, hdr, len, 0, (struct sockaddr*)&sun, slen);
	if (ret == -1 ) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			ret = CCI_EAGAIN;
			break;
		default:
			debug(CCI_DB_CONN, "%s: sendto(%s) failed with %s",
				__func__, sconn->name, strerror(errno));
			ret = CCI_ERROR;
			break;
		}
	} else if (ret != len) {
		debug(CCI_DB_CONN, "%s: sendto(%s) returned only %d of expected %d bytes",
			__func__, sconn->name, ret, len);
		ret = CCI_ENOBUFS;
		goto out;
	}

	ret = 0;
   out:
	CCI_EXIT;
	return ret;
}

static int
sm_handle_connect_ack(cci__ep_t *ep, void *buffer)
{
	int ret = 0;

	return ret;
}

static int
sm_progress_sock(cci__ep_t *ep)
{
	int ret = 0, len = 0;
	sm_ep_t *sep = ep->priv;
	sm_conn_hdr_t *hdr = NULL;
	struct sockaddr_un sun;
	socklen_t slen = sizeof(sun);
	char buffer[1024 + sizeof(*hdr)];

	memset(&sun, 0, slen);

	ret = recvfrom(sep->sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sun, &slen);
	if (ret == -1) {
		ret = errno;
		if (ret != EAGAIN)
			debug(CCI_DB_CONN, "%s: recvfrom() failed with %s",
					__func__, strerror(ret));
		goto out;
	}

	hdr = (void*)buffer;
	len = ret;

	debug(CCI_DB_CONN, "%s: recv'd %s with %d bytes from sm://%s", __func__,
		sm_conn_msg_str(hdr->generic.type), len, sun.sun_path);

	switch (hdr->generic.type) {
	case SM_CMSG_CONNECT:
		len -= sizeof(*hdr);
		ret = sm_handle_connect(ep, sun.sun_path, buffer, len);
		break;
	case SM_CMSG_CONN_REPLY:
		ret = sm_handle_connect_reply(ep, buffer);
		break;
	case SM_CMSG_CONN_ACK:
		ret = sm_handle_connect_ack(ep, buffer);
		break;
	default:
		debug(CCI_DB_CONN, "%s: recv'd unknown connection message type %d "
			"from sm://%s - dropping message", __func__,
			hdr->generic.type, sun.sun_path);
		goto out;
	}

    out:
	return ret;
}

static int
sm_write(cci__ep_t *ep, cci__conn_t *conn, void *buf, int len)
{
	int ret = 0;
	sm_conn_t *sconn = conn->priv;

	ret = write(sconn->fifo, buf, len);
	if (ret == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
		case ENOBUFS:
			ret = CCI_EAGAIN;
			break;
		default:
			ret = CCI_ERROR;
			goto out;
		}
	} else if (ret != len) {
		debug(CCI_DB_MSG, "%s: write(%s) returned only %d of expected %d bytes",
			__func__, sconn->name, ret, len);
		ret = CCI_ERROR;
		goto out;
	}

	ret = 0;
    out:
	debug(CCI_DB_MSG, "%s: writing %d bytes to %s's fifo %s (ret %d)",
		__func__, len, conn->uri, ret ? "failed" : "succeeded", ret);

	return ret;
}

static int
sm_handle_send(cci__ep_t *ep, cci__conn_t *conn, sm_hdr_t *hdr)
{
	int ret = 0;
	sm_conn_t *sconn = conn->priv;
	cci__evt_t *evt = &sconn->rxs[hdr->send.offset];

	/* evt->event.type = CCI_EVENT_RECV; */
	evt->event.recv.ptr = &sconn->rx->buf[hdr->send.offset * SM_LINE];
	evt->event.recv.len = hdr->send.len;
	/* evt->event.recv.connection = &conn->connection; */
	evt->priv = (void*)((uintptr_t) hdr->send.offset);

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
	pthread_mutex_unlock(&ep->lock);

	debug(CCI_DB_MSG, "%s: received SEND from %s (offset %u) len %u",
		__func__, conn->uri, hdr->send.offset, hdr->send.len);

	return ret;
}

static int
sm_handle_rma_write(cci__ep_t *ep, sm_hdr_t hdr)
{
	int ret = 0;

	return ret;
}

static int
sm_handle_rma_read(cci__ep_t *ep, sm_hdr_t hdr)
{
	int ret = 0;

	return ret;
}

static int
sm_handle_rma_ack(cci__ep_t *ep, sm_hdr_t hdr)
{
	int ret = 0;

	return ret;
}

static void
sm_progress_conn(cci__ep_t *ep, cci__conn_t *conn);

static int
sm_progress_fifo(cci__ep_t *ep)
{
	int ret = 0, id = 0, len = sizeof(id);
	sm_ep_t *sep = ep->priv;
	cci__conn_t *conn = NULL;

	return 0;

	ret = read(sep->fifo, &id, len);
	if (ret == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
		case ENOBUFS:
		case ENOMEM:
			break;
		default:
			debug(CCI_DB_WARN, "%s: read(fifo) failed with %s",
					__func__, strerror(errno));
			break;
		}
		ret = CCI_EAGAIN;
		goto out;
	} else if (ret != len) {
		debug(CCI_DB_WARN, "%s: read(fifo) only returned %d of %d bytes requested",
				__func__, ret, len);
		ret = CCI_EAGAIN;
		goto out;
	}

	ret = sm_find_conn(ep, id, &conn);
	if (!ret)
		sm_progress_conn(ep, conn);

    out:
	return ret;
}

static void
sm_progress_conn_tree(const void *nodep, const VISIT which, const int depth)
{
	cci_connection_t *connection = NULL;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;
	sm_conn_t *sconn = NULL;

	switch (which) {
		case preorder:
			sconn = *(sm_conn_t**)nodep;
			conn = sconn->conn;
			connection = &conn->connection;
			ep = container_of(connection->endpoint, cci__ep_t, endpoint);
			sm_progress_conn(ep, conn);
			break;
		case postorder:
			break;
		case endorder:
			break;
		case leaf:
			sconn = *(sm_conn_t**)nodep;
			conn = sconn->conn;
			connection = &conn->connection;
			ep = container_of(connection->endpoint, cci__ep_t, endpoint);
			sm_progress_conn(ep, conn);
			break;
	}
	return;
}

static void
sm_progress_conns(cci__ep_t *ep)
{
	int ret = 0;
	sm_ep_t *sep = ep->priv;

	if (!sep->conns)
		return;

	ret = pthread_rwlock_rdlock(&sep->conns_lock);
	if (ret) {
		debug(CCI_DB_WARN, "%s: pthread_rwlock_rdlock() failed with %s",
				__func__, strerror(ret));
		goto out;
	}

	twalk(sep->conns, sm_progress_conn_tree);

	pthread_rwlock_unlock(&sep->conns_lock);
    out:
	return;
}

static int
sm_progress_ep(cci__ep_t *ep)
{
	static int cnt = 0;

	if (0 && (cnt++ & 0x1000000) == 0x1000000) {
		sm_progress_sock(ep);
		sm_progress_fifo(ep);
	}
	sm_progress_conns(ep);

	return 0;
}

static int ctp_sm_get_event(cci_endpoint_t * endpoint,
			      cci_event_t ** event)
{
	int ret = 0;
	cci__ep_t *ep = NULL;
	cci__evt_t *ev = NULL;

	CCI_ENTER;

	ep = container_of(endpoint, cci__ep_t, endpoint);
	sm_progress_ep(ep);

	pthread_mutex_lock(&ep->lock);
	ev = TAILQ_FIRST(&ep->evts);

	if (ev) {
		char one = 0;
		sm_ep_t *sep = ep->priv;

		TAILQ_REMOVE(&ep->evts, ev, entry);
		if (sep->pipe[0] && TAILQ_EMPTY(&ep->evts)) {
			debug(CCI_DB_EP, "%s: reading from pipe", __func__);
			read(sep->pipe[0], &one, 1);
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

static int
sm_return_connect_request(cci_event_t *event)
{
	int ret = 0;
	cci__evt_t *evt = container_of(event, cci__evt_t, event);

	free((void*)evt->event.request.data_ptr);
	free(evt);

	return ret;
}

static int
sm_return_connect(cci_event_t *event)
{
	int ret = 0;
	cci__evt_t *evt = container_of(event, cci__evt_t, event);

	free(evt);

	return ret;
}

static int
sm_return_accept(cci_event_t *event)
{
	int ret = 0;
	cci__evt_t *evt = container_of(event, cci__evt_t, event);

	free(evt);

	return ret;
}

static void
sm_return_send(cci_event_t *event)
{
	cci__evt_t *evt = container_of(event, cci__evt_t, event);

	if (evt->priv) {
		/* TODO handle RMA */
	}
	free(evt);
	return;
}

static int
sm_reserve_conn_buffer(sm_conn_buffer_t *cb, uint32_t len, int *offset)
{
	int ret = 0, cnt = (len & SM_MASK ? 1 : 0) + (len >> SM_SHIFT), i = 0;
	uint64_t avail = 0, bits = ((uint64_t)1 << cnt) - 1, new = 0;

	debug(CCI_DB_MSG, "%s: requesting %d bytes (cnt %d bits 0x%"PRIx64")",
		__func__, len, cnt, bits);

	for (i = 0; i < (63 - cnt); i++) {
    again:
		avail = read_u64(&cb->avail, __ATOMIC_RELAXED);
		if (!avail) {
			debug(CCI_DB_MSG, "%s: avail 0x%"PRIx64, __func__, avail);
			ret = ENOBUFS;
			goto out;
		}
		if ((avail & bits) == bits) {
			new = avail & ~bits;
			if (compare_and_swap_u64(&cb->avail, avail, new,
						__ATOMIC_SEQ_CST)) {
				debug(CCI_DB_MSG, "%s: bits 0x%"PRIx64" avail 0x%"PRIx64" "
					"new 0x%"PRIx64" offset %u", __func__, bits,
					avail, new, i);
				*offset = i;
				goto out;
			} else {
				goto again;
			}
		}
		bits <<= 1;
	}

	bits = ((uint64_t)1 << cnt) - 1;
	debug(CCI_DB_MSG, "%s: bits 0x%"PRIx64" avail 0x%"PRIx64, __func__, bits, avail);

	ret = CCI_ENOBUFS;

    out:
	return ret;
}

static void
sm_release_conn_buffer(sm_conn_buffer_t *cb, uint32_t len, int offset)
{
	int cnt = (len & SM_MASK ? 1 : 0) + (len >> SM_SHIFT);
	uint64_t avail = 0, bits = (((uint64_t)1 << cnt) - 1) << offset;

    again:
	avail = read_u64(&cb->avail, __ATOMIC_RELAXED);
	debug(CCI_DB_MSG, "%s: bits 0x%"PRIx64" avail 0x%"PRIx64, __func__, bits, avail);
	if (avail & bits)
		debug(CCI_DB_WARN, "%s: bits 0x%"PRIx64" avail 0x%"PRIx64,
			__func__, bits, avail);
	assert((avail & bits) == 0);

	if (!compare_and_swap_u64(&cb->avail, avail, avail | bits, __ATOMIC_SEQ_CST))
		goto again;

	return;
}

static void
sm_return_recv(cci_event_t *event)
{
	cci__evt_t *evt = container_of(event, cci__evt_t, event);
	cci__conn_t *conn = evt->conn;
	sm_conn_t *sconn = conn->priv;

	sm_release_conn_buffer(sconn->rx, event->recv.len, (int)((uintptr_t)evt->priv));

	return;
}

static int ctp_sm_return_event(cci_event_t * event)
{
	int ret = CCI_SUCCESS;

	CCI_ENTER;

	switch (event->type) {
	case CCI_EVENT_CONNECT_REQUEST:
		ret = sm_return_connect_request(event);
		break;
	case CCI_EVENT_CONNECT:
		ret = sm_return_connect(event);
		break;
	case CCI_EVENT_ACCEPT:
		ret = sm_return_accept(event);
		break;
	case CCI_EVENT_SEND:
		sm_return_send(event);
		break;
	case CCI_EVENT_RECV:
		sm_return_recv(event);
		break;
	default:
		debug(CCI_DB_INFO, "%s: ignoring %s", __func__,
				cci_event_type_str(event->type));
		break;
	}

	CCI_EXIT;
	return ret;
}

static int
sm_progress_conn_ring(cci__ep_t *ep, cci__conn_t *conn)
{
	int ret = 0;
	sm_conn_t *sconn = conn->priv;
	uint32_t val = 0;
	sm_hdr_t *hdr = (sm_hdr_t *)&val;

	if (!sconn->rx)
		return CCI_EAGAIN;

	ret = ring_remove(&sconn->rx->ring, &val);
	if (ret)
		goto out;

	switch (hdr->generic.type) {
	case SM_MSG_SEND:
		ret = sm_handle_send(ep, conn, hdr);
		break;
	case SM_MSG_RMA_WRITE:
		break;
	case SM_MSG_RMA_READ:
		break;
	case SM_MSG_RMA_ACK:
		break;
	default:
		debug(CCI_DB_MSG, "%s: unknown header type %d from %s", __func__,
				hdr->generic.type, conn->uri);
		ret = CCI_ERROR;
	}

    out:
	return ret;
}

static void
sm_progress_conn(cci__ep_t *ep, cci__conn_t *conn)
{
	sm_progress_conn_ring(ep, conn);

	return;
}

static int ctp_sm_send(cci_connection_t * connection,
			 const void *msg_ptr, uint32_t msg_len,
			 const void *context, int flags)
{
	int ret = 0, offset = 0;
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	cci__conn_t *conn = container_of(connection, cci__conn_t, connection);
	sm_conn_t *sconn = conn->priv;
	cci__evt_t *evt = NULL;
	sm_hdr_t hdr;

	CCI_ENTER;

	if (!smglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	if (!(flags & CCI_FLAG_SILENT)) {
		evt = calloc(1, sizeof(*evt));
		if (!evt) {
			ret = CCI_ENOMEM;
			goto out;
		}

		evt->event.type = CCI_EVENT_SEND;
		evt->event.send.status = CCI_SUCCESS; /* for now */
		evt->event.send.connection = connection;
		evt->event.send.context = (void *)context;
		evt->ep = ep;
		evt->conn = conn;
		evt->priv = NULL;
	}

	if (msg_len) {
		void *addr = NULL;

		ret = sm_reserve_conn_buffer(sconn->tx, msg_len, &offset);
		if (ret)
			goto out;

		addr = &sconn->tx->buf[offset * SM_LINE];
		memcpy(addr, msg_ptr, msg_len);
		mb();
	}

	hdr.send.type = SM_MSG_SEND;
	hdr.send.offset = offset;
	hdr.send.len = msg_len;

    again:
	ret = ring_insert(&sconn->tx->ring, *((uint32_t*)&hdr.u32));
	if (ret)
		goto again;

	if (!(flags & CCI_FLAG_SILENT)) {
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
		pthread_mutex_unlock(&ep->lock);
	}

    out:
	debug(CCI_DB_MSG, "%s: sending %u bytes to %s %s (%d)", __func__,
		msg_len, conn->uri, ret ? "failed" : "succeeded", ret);

	if (ret)
		free(evt);

	CCI_EXIT;
	return ret;
}

static int ctp_sm_sendv(cci_connection_t * connection,
			  const struct iovec *data, uint32_t iovcnt,
			  const void *context, int flags)
{
	int ret = 0, i = 0, offset = 0;
	uint32_t len = 0;
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	cci__conn_t *conn = container_of(connection, cci__conn_t, connection);
	sm_conn_t *sconn = conn->priv;
	cci__evt_t *evt = NULL;
	sm_hdr_t hdr;

	CCI_ENTER;

	if (!smglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	if (!(flags & CCI_FLAG_SILENT)) {
		evt = calloc(1, sizeof(*evt));
		if (!evt) {
			ret = CCI_ENOMEM;
			goto out;
		}

		evt->event.type = CCI_EVENT_SEND;
		evt->event.send.status = CCI_SUCCESS; /* for now */
		evt->event.send.connection = connection;
		evt->event.send.context = (void *)context;
		evt->ep = ep;
		evt->conn = conn;
		evt->priv = NULL;
	}

	if (iovcnt) {
		void *addr = NULL;

		for (i = 0; i < (int) iovcnt; i++)
			len += data[i].iov_len;

		ret = sm_reserve_conn_buffer(sconn->tx, len, &offset);
		if (ret)
			goto out;

		addr = &sconn->tx->buf[offset * SM_LINE];
		for (i = 0; i < (int) iovcnt; i++) {
			memcpy(addr, data[i].iov_base, data[i].iov_len);
			addr = (void*)((uintptr_t)addr + data[i].iov_len);
		}
		mb();
	}

	hdr.send.type = SM_MSG_SEND;
	hdr.send.offset = offset;
	hdr.send.len = len;

    again:
	ret = ring_insert(&sconn->tx->ring, *((uint32_t*)&hdr.u32));
	if (ret)
		goto again;

	if (!(flags & CCI_FLAG_SILENT)) {
		pthread_mutex_lock(&ep->lock);
		TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
		pthread_mutex_unlock(&ep->lock);
	}

    out:
	debug(CCI_DB_MSG, "%s: sending %u bytes to %s %s (%d)", __func__,
		len, conn->uri, ret ? "failed" : "succeeded", ret);

	if (ret)
		free(evt);

	CCI_EXIT;
	return ret;
}

static int ctp_sm_rma_register(cci_endpoint_t * endpoint,
				 void *start, uint64_t length,
				 int flags, cci_rma_handle_t ** rma_handle)
{
	CCI_ENTER;

	debug(CCI_DB_INFO, "%s", "In sm_rma_register\n");

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_sm_rma_deregister(cci_endpoint_t * endpoint, cci_rma_handle_t * rma_handle)
{
	CCI_ENTER;

	debug(CCI_DB_INFO, "%s", "In sm_rma_deregister\n");

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_sm_rma(cci_connection_t * connection,
			const void *msg_ptr, uint32_t msg_len,
			cci_rma_handle_t * local_handle, uint64_t local_offset,
			cci_rma_handle_t * remote_handle, uint64_t remote_offset,
			uint64_t data_len, const void *context, int flags)
{
	CCI_ENTER;

	debug(CCI_DB_INFO, "%s", "In sm_rma\n");

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}
