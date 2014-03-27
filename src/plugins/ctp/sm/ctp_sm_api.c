/*
 * Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/private_config.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
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
	cci_device_t **devices;
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
 * Available ids do not have a bit set.
 * If none are available, allocate a new block.
 */
static int
sm_get_ep_id(cci__dev_t *dev, uint32_t *id)
{
	int ret = CCI_SUCCESS, i = 0, found = 0;
	uint32_t shift = 0;
	uint64_t *b = NULL, inverted = 0;
	sm_dev_t *sdev = dev->priv;

	pthread_mutex_lock(&dev->lock);
	for (i = 0; i < (int) sdev->num_blocks; i++) {
		b = &sdev->ids[i];
		if (*b != ~((uint64_t)0)) {
			/* There is a bit available in this block.
			 * We will use find-first-set-long (ffsl) since
			 * there is no first-first-zero so we need to
			 * invert the block. */
			inverted = ~(*b);
			shift = (uint32_t) ffsl(inverted);
			assert(shift);	/* it must find a bit */
			shift--;
			assert((*b & ((uint64_t)1 << shift)) == 0);
			*b |= (((uint64_t)1) << shift);
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
		*b |= (uint64_t)1;
	}
out:
	pthread_mutex_unlock(&dev->lock);

	if (!ret)
		*id = shift + sdev->id;

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
	shift = (id % SM_BLOCK_SIZE);

	pthread_mutex_lock(&dev->lock);
	b = &sdev->ids[i];
	assert(*b & ((uintptr_t)1 << shift));
	*b &= ~((uint64_t)1 << shift);
	pthread_mutex_unlock(&dev->lock);

	return ret;
}

static inline int
check_block(uint64_t block, int cnt, int shift, int *offset)
{
	int ret = 0, i = 0;
	uint64_t bits = ((uint64_t)1 << cnt) - 1;

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
		printf("%s: *block=0x%llx bits=0x%llx\n", __func__, *block, bits);
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
sm_buffer_reserve(sm_buffer_t *sb, int len, void **addrp)
{
	int ret = EAGAIN, i = sb->last_block, j = 0, k = 0;
	int cnt = 0, block_offset = sb->block_offset;

	if (!sb || !len ||!addrp)
		return EINVAL;

	cnt = (len & sb->mask ? 1 : 0) + (len >> sb->shift);

	/* If length is greater than 64 (bits) cache lines,
	 * return error */
	if (len > (sb->min_len * 64))
		return EMSGSIZE;

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
		*addrp = (void*) ((uintptr_t)sb->addr +
				(((uintptr_t)i * 64 + block_offset) * sb->min_len));
	}

	return ret;
}

static int
sm_buffer_release(sm_buffer_t *sb, void *addr, int len)
{
	int ret = 0, i = 0, j = 0, cnt = 0;
	int offset = 0;
	uint64_t bits = 0, *b = NULL;

	if (!len)
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

	b = &sb->blocks[i];

	if (i < sb->num_blocks - 1)
		j = i + 1;
	else
		j = 0;

	if (offset + cnt <= 64) {
		bits = bits << offset;
		if (*b & bits) {
			printf("%s: *b=0x%llx bits=0x%llx\n", __func__, *b, bits);
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
			printf("%s: offset=%d len=%d\n", __func__,
					(int)((uintptr_t)addr - (uintptr_t)sb->addr), len);
			printf("%s: *b=0x%llx hi_bits=0x%llx\n", __func__, *b, hi_bits);
			printf("%s: *n=0x%llx lo_bits=0x%llx\n", __func__, *n, lo_bits);
			ret = EINVAL;
			goto out;
		}

		*b = *b | hi_bits;
		*n = *n | lo_bits;
	}

    out:
	return ret;
}

static int ctp_sm_create_endpoint(cci_device_t * device,
				    int flags,
				    cci_endpoint_t ** endpointp,
				    cci_os_handle_t * fd)
{
	int ret = CCI_SUCCESS, len = 0;
	cci__dev_t *dev = NULL;
	cci__ep_t *ep = NULL;
	sm_ep_t *sep = NULL;
	struct cci_endpoint *endpoint = (struct cci_endpoint *) *endpointp;
	sm_dev_t *sdev = NULL;
	struct sockaddr_un sun;
	char name[MAXPATHLEN]; /* max UNIX domain socket name */

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
	ep->buffer_len = dev->device.max_send_size + SM_HDR_LEN;
	ep->tx_timeout = 0;

	sep = ep->priv;

	ret = sm_get_ep_id(dev, &sep->id);
	if (ret) goto out;

	/* If the path length plus enough room for a uint32_t and NULL
	 * exceeds the sizeof name (sun.sun_path) length, bail */
	if ((strlen(sdev->path) + 12) > sizeof(name)) {
		ret = CCI_EINVAL;
		goto out;
	}

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s/%u", sdev->path, sep->id);

	ep->uri = strdup(name);
	if (!ep->uri) {
		ret = CCI_ENOMEM;
		goto out;
	}

	ret = sm_create_path(ep->uri);
	if (ret)
		goto out;

	/* Create FIFO for receiving headers */

	/* If there is not enough space to append "/fifo", bail */
	if (strlen(ep->uri) >= (sizeof(name) - 6)) {
		ret = CCI_EINVAL;
		goto out;
	}

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s/fifo", ep->uri);

	unlink(name);
	ret = mkfifo(name, 0622);
	if (ret) {
		debug(CCI_DB_WARN, "%s: mkfifo(%s) failed with %s", __func__,
				name, strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}

	ret = open(name, O_RDWR);
	if (ret == -1) {
		debug(CCI_DB_WARN, "%s: open(%s) failed with %s", __func__,
				name, strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}
	sep->fifo = ret;

	/* Create mmap send buffer */

	/* If there is not enough space to append "/msgs", bail */
	if (strlen(ep->uri) >= (sizeof(name) - 6)) {
		debug(CCI_DB_WARN, "%s: path %s/msgs is too long", __func__, ep->uri);
		ret = CCI_EINVAL;
		goto out;
	}

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "/cci-sm-%u-%u", getpid(), sep->id);

	shm_unlink(name);

	ret = shm_open(name, O_CREAT | O_RDWR, 0666);
	if (ret == -1) {
		debug(CCI_DB_WARN, "%s: shm_open(%s) failed with %s", __func__,
				name, strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}
	sep->msgs = ret;

	len = ep->tx_buf_cnt * device->max_send_size;

	ret = ftruncate(sep->msgs, len);
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

	sep->tx_buf->addr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, sep->msgs, 0);
	if (sep->tx_buf->addr == MAP_FAILED) {
		debug(CCI_DB_WARN, "%s: mmap() failed with %s", __func__,
				strerror(errno));
		ret = CCI_ERROR;
		goto out;
	}

	/* Create listening socket for connection setup */

	/* If there is not enough space to append "/sock", bail */
	if (strlen(ep->uri) >= (sizeof(name) - 6)) {
		ret = CCI_EINVAL;
		goto out;
	}

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s/sock", ep->uri);

	memset(&sun, 0, sizeof(sun));
	sun.sun_len = strlen(name);
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path, name, sun.sun_len);

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

out:
	if (ret) {
		if (sep) {
			char name[MAXPATHLEN];

			if (sep->msgs) {
				memset(name, 0, sizeof(name));
				snprintf(name, sizeof(name), "/cci-sm-%u-%u",
						getpid(), sep->id);
				shm_unlink(name);
			}
			if (sep->sock) {
				close(sep->sock);
				memset(name, 0, sizeof(name));
				snprintf(name, sizeof(name), "%s/sock", ep->uri);
				unlink(name);
			}
			if (sep->fifo) {
				close(sep->fifo);
				memset(name, 0, sizeof(name));
				snprintf(name, sizeof(name), "%s/fifo", ep->uri);
				unlink(name);
			}
			if (ep->uri) {
				rmdir(ep->uri);
				free(ep->uri);
			}
			sm_put_ep_id(dev, sep->id);
			free(sep);
		}
	}
	CCI_EXIT;
	return ret;
}

static int ctp_sm_destroy_endpoint(cci_endpoint_t * endpoint)
{
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	cci__dev_t *dev = ep->dev;

	CCI_ENTER;

	free(ep->uri);

	if (ep->priv) {
		sm_ep_t *sep = ep->priv;

		sm_put_ep_id(dev, sep->id);
		free(sep);
		ep->priv = NULL;
	}

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_sm_accept(cci_event_t *event, const void *context)
{
	CCI_ENTER;

	debug(CCI_DB_INFO, "%s", "In sm_accept\n");

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_sm_reject(cci_event_t *event)
{
	CCI_ENTER;

	debug(CCI_DB_INFO, "%s", "In sm_reject\n");

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_sm_connect(cci_endpoint_t * endpoint, const char *server_uri,
			    const void *data_ptr, uint32_t data_len,
			    cci_conn_attribute_t attribute,
			    const void *context, int flags, const struct timeval *timeout)
{
	CCI_ENTER;

	debug(CCI_DB_INFO, "%s", "In sm_connect\n");

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
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

static int ctp_sm_get_event(cci_endpoint_t * endpoint,
			      cci_event_t ** event)
{
	CCI_ENTER;

	debug(CCI_DB_INFO, "%s", "In sm_get_event\n");

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_sm_return_event(cci_event_t * event)
{
	CCI_ENTER;

	debug(CCI_DB_INFO, "%s", "In sm_return_event\n");

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
}

static int ctp_sm_send(cci_connection_t * connection,
			 const void *msg_ptr, uint32_t msg_len,
			 const void *context, int flags)
{
	CCI_ENTER;

	debug(CCI_DB_INFO, "%s", "In sm_send\n");

	CCI_EXIT;
	return CCI_ERR_NOT_IMPLEMENTED;
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
