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

#include "cci.h"
#include "plugins/ctp/ctp.h"
#include "ctp_sm.h"

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
	char *tmp = NULL, *dir = NULL, *new = NULL;

	if (!path || (len = strlen(path)) == 0)
		return CCI_EINVAL;

	tmp = strdup(path);
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
				ret = mkdir(new, 0700);
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
	free(tmp);
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
					const char *path = *arg + 5;
					char cwd[MAXPATHLEN], *c = NULL;


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

					memset(dname, 0, sizeof(dname));
					snprintf(dname, sizeof(dname), "%s/%u", path, pid);
					sdev->path = strdup(dname);
					if (!sdev->path) {
						ret = CCI_ENOMEM;
						goto out;
					}
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

			if (sdev->path == NULL) {
				memset(dname, 0, sizeof(dname));
				snprintf(dname, sizeof(dname), "%s/%u", SM_DEFAULT_PATH, pid);
				sdev->path = strdup(dname);
				if (!sdev->path) {
					ret = CCI_ENOMEM;
					goto out;
				}
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
unset_bits(uint64_t *block, uint32_t offset, int cnt)
{
	int ret = 0;
	uint64_t bits = (((uint64_t)1 << cnt) - 1) << offset;

	if (!bits)
		bits = ~((uint64_t)0);

	if ((*block & bits) != bits) {
		debug(CCI_DB_INFO, "%s: *block=0x%"PRIx64" bits=0x%"PRIx64"\n",
				__func__, *block, bits);
		ret = EINVAL;
		goto out;
	}

	*block = *block & ~bits;

    out:
	return ret;
}

static void
sm_buffer_destroy(sm_buffer_t *sb)
{
	if (sb) {
		pthread_mutex_destroy(&sb->lock);
		free(sb->blocks);
	}
	free(sb);
	return;
}

static int
sm_buffer_init(sm_buffer_t **sbp, uint64_t total_len, int min_len)
{
	int ret = 0;
	sm_buffer_t *s = NULL;
	pthread_mutexattr_t ma;

	if (!sbp || !total_len) {
		ret = CCI_EINVAL;
		goto out;
	}

	if (min_len & (min_len - 1)) {
		ret = CCI_EINVAL;
		goto out;
	}

	s = calloc(1, sizeof(*s));
	if (!s) {
		ret = CCI_ENOMEM;
		goto out;
	}

	/* TODO if total_len is not multiple of block size, add one */

	s->len = total_len;
	/* total_len / min_len / bits per block */;
	s->num_blocks = (int) (total_len / (uint64_t)min_len / UINT64_C(64));

	s->blocks = malloc(s->num_blocks * sizeof(*s->blocks));
	if (!s->blocks) {
		ret = CCI_ENOMEM;
		goto out;
	}

	memset(s->blocks, 0xFF, s->num_blocks * sizeof(*s->blocks));

	ret = pthread_mutexattr_init(&ma);
	if (ret)
		goto out;

#ifdef NDEBUG
	ret = pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_NORMAL);
#else
	ret = pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_ERRORCHECK);
#endif
	if (ret) {
		debug(CCI_DB_WARN, "%s: pthread_mutexattr_settype() failed "
				"with %s", __func__, strerror(ret));
		ret = CCI_ERROR;
		goto out;
	}

	ret = pthread_mutex_init(&s->lock, &ma);
	if (ret) {
		debug(CCI_DB_WARN, "%s: pthread_mutex_init() failed "
				"with %s", __func__, strerror(ret));
		ret = CCI_ERROR;
		goto out;
	}

	s->min_len = min_len;
	s->mask = min_len - 1;
	min_len--;
	do {
		min_len = min_len >> 1;
		s->shift++;
	} while (min_len);

	*sbp = s;

    out:
	if (ret)
		sm_buffer_destroy(s);

	return ret;
}

static int
sm_buffer_reserve(sm_buffer_t *sb, int len, uint32_t *offset, void **addrp)
{
	int ret = CCI_ENOBUFS, i = sb->last_block, j = 0, k = 0;
	int cnt = 0, block_offset = sb->block_offset;

	if (!sb || !len ||!addrp)
		return CCI_EINVAL;

	cnt = (len & sb->mask ? 1 : 0) + (len >> sb->shift);

	/* If length is greater than 64 (bits) cache lines,
	 * return error */
	if (len > (sb->min_len * 64))
		return CCI_EMSGSIZE;

	pthread_mutex_lock(&sb->lock);

	do {
		uint64_t tmp = sb->blocks[i], next = 0, top = (uint64_t)1 << 63;

		/* get the next block index */
		if (i < sb->num_blocks - 1)
			j = i + 1;
		else
			j = 0;

		/* if no bits available, check next block */
		if (tmp == 0)
			goto increment;

		/* look within the current block */
		ret = check_block(tmp, cnt, 1, &block_offset);
		if (ret == 0)
			goto done;

		/* perhaps the bits overlap this and the next block... */

		/* how many bits are at the end of this block? */
		k = 0;

		while (tmp & top) {
			k++;
			if (k == cnt - 1)
				break;
			tmp = tmp << 1;
		}
		if (k == 0)
			goto increment;

		next = sb->blocks[j];

		block_offset = 0;
		ret = check_block(next, cnt - k, 0, &block_offset);
		if (ret == 0) {
			block_offset = 64 - k;
			goto done;
		}

		increment:
		i = j;
		block_offset = 0;

	} while (i != sb->last_block);

    done:
	if (!ret) {
		if (block_offset + cnt < 64) {
			sb->last_block = i;
			sb->block_offset = block_offset + cnt;
			ret = unset_bits(&sb->blocks[i], block_offset, cnt);
		} else if (block_offset + cnt == 64) {
			sb->last_block = j;
			sb->block_offset = 0;
			ret = unset_bits(&sb->blocks[i], block_offset, cnt);
		} else {
			sb->last_block = j;
			sb->block_offset = cnt - k;
			ret = unset_bits(&sb->blocks[i], block_offset, k);
			if (!ret)
				ret = unset_bits(&sb->blocks[j], 0, cnt - k);
		}
		*offset = i * 64 + block_offset;
		*addrp = (void*) ((uintptr_t)sb->addr +
				(((uintptr_t)*offset) * sb->min_len));
	}

	pthread_mutex_unlock(&sb->lock);

	return ret;
}

static int
sm_buffer_release(sm_buffer_t *sb, void *addr, int len)
{
	int ret = 0, i = 0, j = 0, cnt = 0;
	int offset = 0;
	uint64_t bits = 0, *b = NULL;

	if (!sb || !len || (!addr && offset < 0))
		return EINVAL;

	cnt = (len & sb->mask ? 1 : 0) + (len >> sb->shift);
	bits = ((uint64_t)1 << cnt) - 1;

	/* if cnt == 64, shift left bits = 0 */
	if (!bits)
		bits = ~((uint64_t)0);

	/* convert addr to cache line index */
	i = (int) (((uintptr_t)addr - (uintptr_t)sb->addr) >> sb->shift);

	/* get offset within the block */
	offset = i & 63;

	/* determine which block has the starting cache line */
	i = i >> 6;

	pthread_mutex_lock(&sb->lock);

	b = &sb->blocks[i];

	if (i < sb->num_blocks - 1)
		j = i + 1;
	else
		j = 0;

	if (offset + cnt <= 64) {
		bits = bits << offset;
		if (*b & bits) {
			debug(CCI_DB_INFO, "%s: *b=0x%"PRIx64" bits=0x%"PRIx64"\n",
					__func__, *b, bits);
			ret = EINVAL;
			goto out;
		}
		*b = *b | bits;
	} else {
		int k = 64 - offset;
		uint64_t *n = &sb->blocks[j];
		uint64_t hi_bits = bits << offset;
		uint64_t lo_bits = bits >> k;

		if (*b & hi_bits || *n & lo_bits) {
			debug(CCI_DB_INFO, "%s: offset=%d len=%d\n", __func__,
					(int)((uintptr_t)addr - (uintptr_t)sb->addr), len);
			debug(CCI_DB_INFO, "%s: *b=0x%"PRIx64" hi_bits=0x%"PRIx64"\n",
					__func__, *b, hi_bits);
			debug(CCI_DB_INFO, "%s: *n=0x%"PRIx64" lo_bits=0x%"PRIx64"\n",
					__func__, *n, lo_bits);
			ret = EINVAL;
			goto out;
		}

		*b = *b | hi_bits;
		*n = *n | lo_bits;
	}

    out:
	pthread_mutex_unlock(&sb->lock);

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

static int ctp_sm_create_endpoint(cci_device_t * device,
				    int flags,
				    cci_endpoint_t ** endpointp,
				    cci_os_handle_t * fd)
{
	int ret = CCI_SUCCESS, len = 0, i = 0, msgs_fd = 0;
	uint32_t id = 0;
	struct cci_endpoint *endpoint = (struct cci_endpoint *) *endpointp;
	cci__dev_t *dev = NULL;
	cci__ep_t *ep = NULL;
	sm_dev_t *sdev = NULL;
	sm_ep_t *sep = NULL;
	sm_tx_t *tx = NULL;
	sm_rx_t *rx = NULL;
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

	TAILQ_INIT(&sep->idle_txs);
	TAILQ_INIT(&sep->idle_rxs);

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

	/* Create FIFO for receiving headers */

	/* If there is not enough space to append "/fifo", bail */
	if (strlen(ep->uri) >= (sizeof(name) - 6)) {
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

	/* Create mmap send buffer */

	/* Store the length of the MMAP buffer in /path/msgs-len.
	 * The peer will need this to correctly mmap the buffer. */

	len = ep->tx_buf_cnt * device->max_send_size;

	/* If there is not enough space to append "/msgs-len", bail */
	if (strlen(name) >= (sizeof(name) - 10)) {
		debug(CCI_DB_WARN, "%s: path %s/msgs-len is too long", __func__, uri);
		ret = CCI_EINVAL;
		goto out;
	}
	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s/msgs-len", uri);
	unlink(name);

	ret = open(name, O_WRONLY|O_CREAT|O_TRUNC, 0666);
	if (ret == -1) {
		ret = CCI_ERROR;
		goto out;
	}
	msgs_fd = ret;

	ret = write(msgs_fd, &len, sizeof(len));
	close(msgs_fd);
	if (ret == -1) {
		ret = CCI_ERROR;
		goto out;
	}

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s/msgs", uri);
	unlink(name);

	ret = open(name, O_RDWR|O_CREAT, 0666);
	if (ret == -1) {
		ret = CCI_ERROR;
		goto out;
	}
	msgs_fd = ret;

	sep->conn_ids = malloc(SM_EP_MAX_CONNS / sizeof(*sep->conn_ids));
	if (!sep->conn_ids) {
		ret = CCI_ENOMEM;
		goto out;
	}
	memset(sep->conn_ids, 0xFF, SM_EP_MAX_CONNS / sizeof(*sep->conn_ids));

	ret = ftruncate(msgs_fd, len);
	if (ret) {
		debug(CCI_DB_WARN, "%s: ftruncate(%s, %d) failed with %s", __func__,
				name, len, strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}

	ret = sm_buffer_init(&sep->tx_buf, len, SM_LINE);
	if (ret) {
		debug(CCI_DB_WARN, "%s: sm_buffer_init() failed with %s",
				__func__, strerror(ret));
		ret = CCI_ERROR;
		goto out;
	}

	sep->tx_buf->addr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, msgs_fd, 0);
	close(msgs_fd);
	if (sep->tx_buf->addr == MAP_FAILED) {
		debug(CCI_DB_WARN, "%s: mmap() of %s failed with %s", __func__,
				name, strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}

	/* Allocate receive buffer */

	len = ep->rx_buf_cnt * device->max_send_size;

	ret = sm_buffer_init(&sep->rx_buf, len, SM_LINE);
	if (ret) {
		debug(CCI_DB_WARN, "%s: sm_buffer_init() failed with %s",
				__func__, strerror(ret));
		ret = CCI_ERROR;
		goto out;
	}

	ret = posix_memalign(&sep->rx_buf->addr, SM_LINE, len);
	if (ret) {
		debug(CCI_DB_WARN, "%s: posix_memalign() failed with %s", __func__,
				strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}

	/* Allocate txs and rxs
	 *
	 * To avoid false-sharing, align each item on a cache line boundary.
	 */

	assert(sizeof(*tx) <= SM_LINE);
	len = ep->tx_buf_cnt * SM_LINE;

	ret = posix_memalign((void**)&sep->txs, SM_LINE, len);
	if (ret)
		goto out;

	for (i = 0; i < (int) ep->tx_buf_cnt; i++) {
		uintptr_t offset = i * SM_LINE;

		tx = (void*)((uintptr_t)sep->txs + offset);
		tx->ctx = SM_TX;
		tx->evt.ep = ep;
		tx->id = i;
		tx->state = SM_TX_INIT;
		TAILQ_INSERT_TAIL(&sep->idle_txs, &tx->evt, entry);
	}

	assert(sizeof(*rx) <= SM_LINE);
	len = ep->rx_buf_cnt * SM_LINE;

	ret = posix_memalign((void**)&sep->rxs, SM_LINE, len);
	if (ret)
		goto out;

	for (i = 0; i < (int) ep->rx_buf_cnt; i++) {
		uintptr_t offset = i * SM_LINE;

		rx = (void*)((uintptr_t)sep->rxs + offset);
		rx->ctx = SM_RX;
		rx->evt.ep = ep;
		TAILQ_INSERT_TAIL(&sep->idle_rxs, &rx->evt, entry);
	}

	/* Create listening socket for connection setup */

	/* If there is not enough space to append "/sock", bail */
	if (strlen(ep->uri) >= (sizeof(name) - 6)) {
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

	ret = fcntl(sep->sock, F_GETFL, 0);
	if (-1 == flags)
		flags = 0;
	ret = fcntl(sep->sock, F_SETFL, flags | O_NONBLOCK);
	if (ret == -1) {
		ret = CCI_ERROR;
		goto out;
	}


	ret = bind(sep->sock, (const struct sockaddr *)&sun, sizeof(sun));
	if (ret) {
		debug(CCI_DB_WARN, "%s: bind() failed with %s", __func__,
				strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}

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
		int len = 0;
		char name[MAXPATHLEN];

		if (sep->sock) {
			close(sep->sock);
			memset(name, 0, sizeof(name));
			snprintf(name, sizeof(name), "%s/sock", path);
			unlink(name);
		}

		/* TODO: Close all open connections */

		/* Free txs, rxs, and buffers */
		free(sep->rxs);
		if (sep->rx_buf)
			free(sep->rx_buf->addr);
		sm_buffer_destroy(sep->rx_buf);

		free(sep->txs);
		if (sep->tx_buf) {
			if (sep->tx_buf->addr) {
				len = ep->tx_buf_cnt * endpoint->device->max_send_size;
				munmap(sep->tx_buf->addr, len);
			}
		}
		sm_buffer_destroy(sep->tx_buf);

		free(sep->conn_ids);

		/* Unlink msgs and msgs-len */
		memset(name, 0, sizeof(name));
		snprintf(name, sizeof(name), "%s/msgs", path);
		unlink(name);

		memset(name, 0, sizeof(name));
		snprintf(name, sizeof(name), "%s/msgs-len", path);
		unlink(name);

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
	int ret = 0, peer_pid = 0, peer_id = 0, len = 0, msgs_fd = 0;
	cci__conn_t *conn = NULL;
	pthread_mutexattr_t ma;
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

	ret = pthread_mutexattr_init(&ma);
	if (ret)
		goto out;

#ifdef NDEBUG
	ret = pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_NORMAL);
#else
	ret = pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_ERRORCHECK);
#endif
	if (ret) {
		debug(CCI_DB_WARN, "%s: pthread_mutexattr_settype() failed "
				"with %s", __func__, strerror(ret));
		ret = CCI_ERROR;
		goto out;
	}

	ret = pthread_mutex_init(&sconn->lock, &ma);
	if (ret) {
		debug(CCI_DB_WARN, "%s: pthread_mutex_init() failed "
				"with %s", __func__, strerror(ret));
		ret = CCI_ERROR;
		goto out;
	}

	TAILQ_INIT(&sconn->queued);
	TAILQ_INIT(&sconn->pending);

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

	/* Open their shared memory object */
	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s/msgs-len", path);
	ret = open(name, O_RDONLY);
	if (ret == -1) {
		debug(CCI_DB_CONN, "%s: unable to open %s's msgs-len", __func__, uri);
		ret = EHOSTUNREACH;
		goto out;
	}
	msgs_fd = ret;

	ret = read(msgs_fd, &len, sizeof(len));
	close(msgs_fd);
	if (ret == -1) {
		debug(CCI_DB_CONN, "%s: unable to read %s's msgs-len", __func__, uri);
		ret = EHOSTUNREACH;
		goto out;
	}

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s/msgs", path);
	ret = open(name, O_RDWR, 0666);
	if (ret == -1) {
		debug(CCI_DB_CONN, "%s: unable to open %s's msgs", __func__, uri);
		ret = EHOSTUNREACH;
		goto out;
	}
	msgs_fd = ret;

	/* MMAP their MSGs buffer */
	sconn->base = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, msgs_fd, 0);
	close(msgs_fd);
	if (sconn->base == MAP_FAILED) {
		debug(CCI_DB_WARN, "%s: mmap() failed with %s", __func__,
				strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}

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
			if (sconn->base)
				munmap(sconn->base, len);
			if (sconn->fifo)
				close(sconn->fifo);
			pthread_mutex_destroy(&sconn->lock);
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
	conn->connection.context = (void*) context;

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
	sm_rx_t *rx = NULL;
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
	rx->evt.event.request.type = CCI_EVENT_CONNECT_REQUEST;
	rx->evt.ep = ep;

	if (len) {
		rx->evt.event.request.data_len = len;
		rx->evt.event.request.data_ptr = calloc(1, len);
		if (!rx->evt.event.request.data_ptr) {
			ret = CCI_ENOMEM;
			goto out;
		}
		memcpy(*((void**)&rx->evt.event.request.data_ptr), p, len);
	}

	ret = sm_create_conn(ep, uri, &conn);
	if (ret) goto out;

	rx->evt.conn = conn;
	conn->connection.attribute = hdr->connect.attribute;

	sconn = conn->priv;
	sconn->state = SM_CONN_PASSIVE;
	sconn->peer_id = hdr->connect.server_id;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
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
			free((void*)rx->evt.event.request.data_ptr);
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

	sconn = conn->priv;
	params = sconn->params;

	free(params->data_ptr);
	free(params);

	evt->event.type = CCI_EVENT_CONNECT;

	memset(&sun, 0, slen);
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path, sconn->name, strlen(sconn->name));

	if (hdr->reply.status == CCI_SUCCESS) {
		sconn->peer_id = hdr->reply.client_id;
		evt->conn = conn;
		evt->event.connect.status = CCI_SUCCESS;
		evt->event.connect.connection = &conn->connection;
		sconn->state = SM_CONN_READY;
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

	pthread_mutex_lock(&ep->lock);
	if (sep->sock_busy) {
		pthread_mutex_unlock(&ep->lock);
		return CCI_EAGAIN;
	}
	sep->sock_busy = 1;
	pthread_mutex_unlock(&ep->lock);

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
	pthread_mutex_lock(&ep->lock);
	sep->sock_busy = 0;
	pthread_mutex_unlock(&ep->lock);

	return ret;
}

static inline sm_tx_t *
sm_get_tx(cci__ep_t *ep)
{
	cci__evt_t *evt = NULL;
	sm_ep_t *sep = ep->priv;
	sm_tx_t *tx = NULL;

	pthread_mutex_lock(&ep->lock);
	evt = TAILQ_FIRST(&sep->idle_txs);
	if (evt) {
		TAILQ_REMOVE(&sep->idle_txs, evt, entry);
		tx = container_of(evt, sm_tx_t, evt);
		tx->state = SM_TX_INIT;
		tx->silent = 0;
		tx->attempt = 0;
		/* tx->offset = 0; */
		/* tx->len = 0; */

		tx->evt.event.send.status = 0;
		tx->evt.event.send.connection = NULL;
		tx->evt.event.send.context = NULL;
		tx->evt.conn = NULL;
		tx->evt.priv = NULL;

		memset(&tx->hdr, 0, sizeof(tx->hdr));

		tx->timestamp = 0;
		tx->rma_op = NULL;
		tx->rma_id = 0;
	}
	pthread_mutex_unlock(&ep->lock);

	return tx;
}

static inline void
sm_put_tx(sm_tx_t *tx)
{
	cci__ep_t *ep = tx->evt.ep;
	sm_ep_t *sep = ep->priv;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_HEAD(&sep->idle_txs, &tx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	return;
}

static inline sm_rx_t *
sm_get_rx(cci__ep_t *ep)
{
	cci__evt_t *evt = NULL;
	sm_ep_t *sep = ep->priv;
	sm_rx_t *rx = NULL;

	pthread_mutex_lock(&ep->lock);
	evt = TAILQ_FIRST(&sep->idle_rxs);
	if (evt) {
		TAILQ_REMOVE(&sep->idle_rxs, evt, entry);
		rx = container_of(evt, sm_rx_t, evt);
		rx->evt.event.recv.ptr = NULL;
		rx->evt.event.recv.len = 0;
		rx->evt.event.recv.connection = NULL;
		rx->evt.conn = NULL;
		rx->evt.priv = NULL;
	}
	pthread_mutex_unlock(&ep->lock);

	return rx;
}

static inline void
sm_put_rx(sm_rx_t *rx)
{
	int ret = 0;
	cci__ep_t *ep = rx->evt.ep;
	sm_ep_t *sep = ep->priv;

	if (rx->evt.event.recv.len) {
		ret = sm_buffer_release(sep->rx_buf, (void *)rx->evt.event.recv.ptr,
				rx->evt.event.recv.len);
		if (ret) {
			debug(CCI_DB_MSG, "%s: rx %p from %s failed to release buffer %p ",
				__func__, (void*)rx, rx->evt.conn->uri,
				rx->evt.event.recv.ptr);
		}
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_HEAD(&sep->idle_rxs, &rx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

	return;
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
sm_handle_send(cci__ep_t *ep, sm_hdr_t hdr)
{
	int ret = 0;
	sm_ep_t *sep = ep->priv;
	cci__conn_t *conn = NULL;
	sm_conn_t *sconn = NULL;
	uint32_t msg_len = 0, unused = 0;
	void *addr = NULL, *peer_addr = NULL;
	sm_rx_t *rx = NULL;

	ret = sm_find_conn(ep, hdr.send.id, &conn);
	if (ret)
		goto out;
	sconn = conn->priv;

	rx = sm_get_rx(ep);
	if (!rx) {
		ret = CCI_ENOBUFS;
		goto out;
	}

	msg_len = hdr.send.len;

	if (msg_len) {
		ret = sm_buffer_reserve(sep->rx_buf, msg_len, &unused, &addr);
		if (ret) {
			goto out;
		}

		peer_addr = (void*)((uintptr_t)sconn->base + (hdr.send.offset * SM_LINE));
		memcpy(addr, peer_addr, msg_len);
	}

	rx->evt.event.type = CCI_EVENT_RECV;
	rx->evt.event.recv.ptr = addr;
	rx->evt.event.recv.len = msg_len;
	rx->evt.event.recv.connection = &conn->connection;

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, &rx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

    out:
	debug(CCI_DB_MSG, "%s: received SEND from %s (conn id %u) len %u ret %d",
		__func__, conn ? conn->uri : "unknown conn", hdr.send.id,
		msg_len, ret);

	if (!ret) {
		hdr.send.type = SM_MSG_SEND_ACK;
		hdr.send.id = sconn->peer_id;
		sm_write(ep, conn, &hdr, sizeof(hdr));
	} else {
		if (rx)
			sm_put_rx(rx);
		if (conn) {
			hdr.send.type = SM_MSG_SEND_NACK;
			hdr.send.id = sconn->peer_id;
			sm_write(ep, conn, &hdr, sizeof(hdr));
		}
	}

	return ret;
}

static int
sm_handle_send_ack(cci__ep_t *ep, sm_hdr_t hdr)
{
	int ret = 0;
	sm_ep_t *sep = ep->priv;
	cci__conn_t *conn = NULL;
	sm_conn_t *sconn = NULL;
	sm_tx_t *tx = NULL;
	uintptr_t addr = (uintptr_t) sep->txs;

	ret = sm_find_conn(ep, hdr.send.id, &conn);
	if (ret)
		goto out;
	sconn = conn->priv;

	tx = (void *)(addr + (hdr.send.seq * SM_LINE));

	assert(tx->hdr.send.offset == hdr.send.offset);
	assert(tx->hdr.send.seq == hdr.send.seq);
	assert(tx->hdr.send.len == hdr.send.len);

	tx->evt.event.send.status = CCI_SUCCESS;

	if (tx->hdr.send.len) {
		ret = sm_buffer_release(sep->tx_buf, tx->evt.priv, tx->hdr.send.len);
		if (ret) {
			debug(CCI_DB_MSG, "%s: tx %u to %s failed to release buffer %p "
				"(offset %u)", __func__, tx->id, conn->uri, tx->evt.priv,
				tx->hdr.send.offset);
		}
	}

	pthread_mutex_lock(&ep->lock);
	TAILQ_INSERT_TAIL(&ep->evts, &tx->evt, entry);
	pthread_mutex_unlock(&ep->lock);

    out:
	debug(CCI_DB_MSG, "%s: received SEND_ACK from %s (conn id %u) tx %d ret %d",
		__func__, conn ? conn->uri : "unknown conn", hdr.send.id,
		tx ? tx->id : -1, ret);

	return ret;
}

static int
sm_handle_send_nack(cci__ep_t *ep, sm_hdr_t hdr)
{
	int ret = 0;

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

static int
sm_progress_fifo(cci__ep_t *ep)
{
	int ret = 0, len = 0;
	sm_ep_t *sep = ep->priv;
	sm_hdr_t hdr;

	pthread_mutex_lock(&ep->lock);
	if (sep->fifo_busy) {
		pthread_mutex_unlock(&ep->lock);
		return CCI_EAGAIN;
	}
	sep->fifo_busy = 1;
	pthread_mutex_unlock(&ep->lock);

	len = sizeof(hdr);
	memset(&hdr, 0, len);

	ret = read(sep->fifo, &hdr, len);
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

	switch (hdr.generic.type) {
	case SM_MSG_SEND:
		ret = sm_handle_send(ep, hdr);
		break;
	case SM_MSG_SEND_ACK:
		ret = sm_handle_send_ack(ep, hdr);
		break;
	case SM_MSG_SEND_NACK:
		ret = sm_handle_send_nack(ep, hdr);
		break;
	case SM_MSG_RMA_WRITE:
		ret = sm_handle_rma_write(ep, hdr);
		break;
	case SM_MSG_RMA_READ:
		ret = sm_handle_rma_read(ep, hdr);
		break;
	case SM_MSG_RMA_ACK:
		ret = sm_handle_rma_ack(ep, hdr);
		break;
	default:
		debug(CCI_DB_WARN, "%s: received unknown message type %d",
				__func__, hdr.generic.type);
		ret = CCI_ERROR;
		break;
	}

    out:
	pthread_mutex_lock(&ep->lock);
	sep->fifo_busy = 0;
	pthread_mutex_unlock(&ep->lock);

	return ret;
}

static void
sm_progress_conn(cci__ep_t *ep, cci__conn_t *conn);

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
	sm_progress_sock(ep);
	sm_progress_fifo(ep);
	sm_progress_conns(ep);

	return 0;
}

static int ctp_sm_get_event(cci_endpoint_t * endpoint,
			      cci_event_t ** event)
{
	int ret = 0;
	cci__ep_t *ep = NULL;
	cci__evt_t *e = NULL;
	cci__evt_t *ev = NULL;

	CCI_ENTER;

	ep = container_of(endpoint, cci__ep_t, endpoint);
	sm_progress_ep(ep);

	pthread_mutex_lock(&ep->lock);
	TAILQ_FOREACH(e, &ep->evts, entry) {
		if (e->event.type == CCI_EVENT_SEND) {
			/* NOTE: if it is blocking, skip it since sendv()
			 *       is waiting on it
			 */
			sm_tx_t *tx = container_of(e, sm_tx_t, evt);
			if (tx->silent) {
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
#if 1
		TAILQ_REMOVE(&ep->evts, ev, entry);
#else
		char one = 0;
		sm_ep_t *sep = ep->priv;

		TAILQ_REMOVE(&ep->evts, ev, entry);
		if (sep->fd && TAILQ_EMPTY(&ep->evts)) {
			debug(CCI_DB_EP, "%s: reading from pipe", __func__);
			read(sep->pipe[0], &one, 1);
			assert(one == 1);
		}
#endif
	} else {
		sm_ep_t *sep = ep->priv;

		ret = CCI_EAGAIN;
		if (TAILQ_EMPTY(&sep->idle_rxs))
			ret = CCI_ENOBUFS;
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
	sm_rx_t *rx = container_of(evt, sm_rx_t, evt);

	free((void*)evt->event.request.data_ptr);
	free(rx);

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
	sm_tx_t *tx = container_of(evt, sm_tx_t, evt);

	sm_put_tx(tx);

	return;
}

static void
sm_return_recv(cci_event_t *event)
{
	cci__evt_t *evt = container_of(event, cci__evt_t, event);
	sm_rx_t *rx = container_of(evt, sm_rx_t, evt);

	sm_put_rx(rx);

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

static void
sm_progress_queued(cci__ep_t *ep, cci__conn_t *conn)
{
	sm_conn_t *sconn = conn->priv;
	cci__evt_t *evt = NULL;
	struct timeval tv;
	uint64_t now;

	gettimeofday(&tv, NULL);
	now = tv.tv_sec * 1000000000 + tv.tv_usec * 1000;

	pthread_mutex_lock(&sconn->lock);

	evt = TAILQ_FIRST(&sconn->queued);
	while (evt) {
		int ret = 0, len = sizeof(sm_hdr_t);
		sm_tx_t *tx = NULL;

		TAILQ_REMOVE(&sconn->queued, evt, entry);
		tx = container_of(evt, sm_tx_t, evt);
		tx->attempt++;
		tx->timestamp = now;
		ret = sm_write(ep, conn, &tx->hdr, len);
		if (ret) {
			TAILQ_INSERT_HEAD(&sconn->queued, &tx->evt, entry);
			break;
		}
		TAILQ_INSERT_TAIL(&sconn->pending, &tx->evt, entry);
		evt = TAILQ_FIRST(&sconn->queued);
	}

	pthread_mutex_unlock(&sconn->lock);

	return;
}

static void
sm_progress_pending(cci__ep_t *ep, cci__conn_t *conn)
{
	sm_conn_t *sconn = conn->priv;
	cci__evt_t *evt = NULL;
	struct timeval tv;
	uint64_t now;

	gettimeofday(&tv, NULL);
	now = tv.tv_sec * 1000000000 + tv.tv_usec * 1000;

	pthread_mutex_lock(&sconn->lock);

	evt = TAILQ_FIRST(&sconn->pending);
	while (evt) {
		int ret = 0, len = sizeof(sm_hdr_t);
		sm_tx_t *tx = NULL;

		tx = container_of(evt, sm_tx_t, evt);
		if (tx->timestamp + (tx->attempt * conn->tx_timeout) < now)
			break;

		tx->attempt++;
		tx->timestamp = now;

		ret = sm_write(ep, conn, &tx->hdr, len);
		if (ret)
			break;

		evt = TAILQ_FIRST(&sconn->pending);
	}

	pthread_mutex_unlock(&sconn->lock);

	return;
}

static void
sm_progress_conn(cci__ep_t *ep, cci__conn_t *conn)
{
	sm_progress_pending(ep, conn);
	sm_progress_queued(ep, conn);

	return;
}

static int ctp_sm_send(cci_connection_t * connection,
			 const void *msg_ptr, uint32_t msg_len,
			 const void *context, int flags)
{
	int ret = 0;
	cci_endpoint_t *endpoint = connection->endpoint;
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	cci__conn_t *conn = container_of(connection, cci__conn_t, connection);
	sm_ep_t *sep = ep->priv;
	sm_conn_t *sconn = conn->priv;
	sm_tx_t *tx = NULL;
	uint32_t offset = 0;
	void *addr = NULL;

	CCI_ENTER;

	if (!smglobals) {
		CCI_EXIT;
		return CCI_ENODEV;
	}

	tx = sm_get_tx(ep);
	if (!tx) {
		ret = CCI_ENOBUFS;
		goto out;
	}

	tx->type = SM_MSG_SEND;
	tx->evt.event.type = CCI_EVENT_SEND;
	tx->evt.event.send.status = CCI_SUCCESS; /* for now */
	tx->evt.event.send.connection = connection;
	tx->evt.event.send.context = (void*)context;
	tx->evt.conn = conn;
	if (flags & CCI_FLAG_SILENT)
		tx->silent = 1;

	if (msg_len) {
		ret = sm_buffer_reserve(sep->tx_buf, msg_len, &offset, &addr);
		if (ret) {
			goto out;
		}

		if (((uintptr_t)addr + msg_len) <
			((uintptr_t)sep->tx_buf->addr + sep->tx_buf->len)) {
			/* the buffer does not wrap, copy the whole message */

			memcpy(addr, msg_ptr, msg_len);
		} else {
			/* the buffer wraps, copy both parts */
			uint32_t wrap = (uint32_t) (((uintptr_t)addr + msg_len) -
				((uintptr_t)sep->tx_buf->addr + sep->tx_buf->len));
			void *tail = (void*)((uintptr_t)msg_ptr + wrap);

			memcpy(addr, msg_ptr, msg_len - wrap);
			memcpy(sep->tx_buf->addr, tail, wrap);

		}
	}
	tx->evt.priv = addr; /* cache address to pass to sm_buffer_release() */

	tx->hdr.send.type = SM_MSG_SEND;
	tx->hdr.send.id = sconn->peer_id;
	tx->hdr.send.offset = offset;
	tx->hdr.send.seq = tx->id;
	tx->hdr.send.len = msg_len;

	pthread_mutex_lock(&sconn->lock);
	TAILQ_INSERT_TAIL(&sconn->queued, &tx->evt, entry);
	pthread_mutex_unlock(&sconn->lock);

	sm_progress_conn(ep, conn);

    out:
	debug(CCI_DB_MSG, "%s: tx %d sending %u bytes to %s %s (%d)", __func__,
		tx ? tx->id : -1, msg_len, conn->uri, ret ? "failed" : "succeeded", ret);

	if (ret) {
		if (addr)
			sm_buffer_release(sep->tx_buf, addr, msg_len);
		if (tx)
			sm_put_tx(tx);
	}
	CCI_EXIT;
	return ret;
}

static int ctp_sm_sendv(cci_connection_t * connection,
			  const struct iovec *data, uint32_t iovcnt,
			  const void *context, int flags)
{
	CCI_ENTER;

	debug(CCI_DB_INFO, "%s", "In sm_sendv\n");

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
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
