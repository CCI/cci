/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2010-2011 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2011 Oak Ridge National Labs.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include "cci/config.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#ifdef HAVE_IFADDRS_H
#include <net/if.h>
#include <ifaddrs.h>
#endif
#ifdef __linux__
#include <linux/ethtool.h>
#include <linux/sockios.h>
#endif

#include "cci.h"
#include "cci_lib_types.h"
#include "plugins/base/public.h"
#include "plugins/ctp/ctp.h"
#include "plugins/ctp/base/public.h"
#include "cci-api.h"

int cci__debug = CCI_DB_DFLT;
cci__globals_t *globals = NULL;
int initialized = 0;
pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;

static inline void cci__get_debug_env(void)
{
	int mask = 0;
	char *debug = NULL;

	debug = getenv("CCI_DEBUG");
	if (!(debug && debug[0] != '\0'))
		return;

	do {
		char *comma = NULL;
		char *next = NULL;

		comma = strchr(debug, ',');
		if (comma) {
			/* find the comma */
			*comma = '\0';
			next = comma + 1;
		} else {
			/* last item */
			next = NULL;
		}
		if (0 == strncmp(debug, "mem", 3)) {
			mask |= CCI_DB_MEM;
		} else if (0 == strncmp(debug, "msg", 3)) {
			mask |= CCI_DB_MSG;
		} else if (0 == strncmp(debug, "peer", 4)) {
			mask |= CCI_DB_PEER;
		} else if (0 == strncmp(debug, "conn", 4)) {
			mask |= CCI_DB_CONN;
		} else if (0 == strncmp(debug, "err", 3)) {
			mask |= CCI_DB_ERR;
		} else if (0 == strncmp(debug, "func", 4)) {
			mask |= CCI_DB_FUNC;
		} else if (0 == strncmp(debug, "info", 4)) {
			mask |= CCI_DB_INFO;
		} else if (0 == strncmp(debug, "warn", 4)) {
			mask |= CCI_DB_WARN;
		} else if (0 == strncmp(debug, "drvr", 4)) {
			mask |= CCI_DB_DRVR;
		} else if (0 == strncmp(debug, "all", 3)) {
			mask |= CCI_DB_ALL;
		} else {
			debug(CCI_DB_WARN, "unknown debug level \"%s\"", debug);
		}
		debug = next;
	} while (debug);

	cci__debug |= mask;

	return;
}

#define CCI_BUF_LEN             1024

void cci__free_args(char **args)
{
	int i;

	if (!args)
		return;

	for (i = 0; args[i] != NULL; i++) {
		if (args[i])
			free(args[i]);
	}
	free(args);

	return;
}

void cci__free_dev(cci__dev_t * dev)
{
	struct cci_device *device;

	if (!dev)
		return;

	device = &dev->device;

	if (device->name)
		free((char *)device->name);

	if (device->info)
		free((char *)device->info);

	cci__free_args((char **)device->conf_argv);

	free((char *)device->transport);

	/* TODO dev->priv */

	free(dev);

	return;
}

static int cci__free_configfile_devs(const char *reason)
{
	cci__dev_t *dev;

	while (!TAILQ_EMPTY(&globals->configfile_devs)) {
		dev = TAILQ_FIRST(&globals->configfile_devs);
		TAILQ_REMOVE(&globals->configfile_devs, dev, entry);
		if (reason)
			debug(CCI_DB_DRVR,
			      "destroying device [%s] (transport %s), %s",
			      dev->device.name, dev->device.transport, reason);
		cci__free_dev(dev);
	}

	return CCI_ENOMEM;
}

void cci__init_dev(cci__dev_t *dev)
{
	struct cci_device *device = &dev->device;

	dev->priority = -1; /* tell the transport it must initialize it if we didn't */
	dev->is_default = 0;
	TAILQ_INIT(&dev->eps);
	pthread_mutex_init(&dev->lock, NULL);
	device->up = 0;

	device->rate = 0;		/* unknown */
	device->pci.domain = -1;	/* per CCI spec */
	device->pci.bus = -1;		/* per CCI spec */
	device->pci.dev = -1;		/* per CCI spec */
	device->pci.func = -1;		/* per CCI spec */
}

/* only used by backends when adding ready devices to the main list
 * must be called with globals->lock held */
void cci__add_dev(cci__dev_t * dev)
{
	int done = 0;
	cci__dev_t *dd;

	assert(NULL != dev->plugin);

	debug(CCI_DB_DRVR,
	      "adding device [%s] (transport %s)",
	      dev->device.name, dev->device.transport);

	/* walk list and insert in order by up/default/priority */
	TAILQ_FOREACH(dd, &globals->devs, entry) {
		if (dev->device.up < dd->device.up)
			continue;
		if (dev->device.up == dd->device.up
		    && dev->is_default < dd->is_default)
			continue;
		if (dev->device.up == dd->device.up
		    && dev->is_default == dd->is_default
		    && dev->priority < dd->priority)
			continue;
		if (dev->device.up == dd->device.up
		    && dev->is_default == dd->is_default
		    && dev->priority == dd->priority
		    && dev->device.rate < dd->device.rate)
			continue;

		TAILQ_INSERT_BEFORE(dd, dev, entry);
		done = 1;
		break;
	}
	if (!done) {
		TAILQ_INSERT_TAIL(&globals->devs, dev, entry);
	}
	return;
}

#ifdef HAVE_GETIFADDRS
int cci__get_dev_ifaddrs_info(cci__dev_t *dev, struct ifaddrs *ifaddr)
{
	struct cci_device * device = &dev->device;
	struct ethtool_drvinfo edi;
	struct ethtool_cmd ecmd;
	struct ifreq ifr;
	int sockfd;

	/* mark the MSS as unknown in case we fail later */
	device->max_send_size = -1;

	/* up flag is easy */
	device->up = (ifaddr->ifa_flags & IFF_UP != 0);

	debug(CCI_DB_INFO,
	      "querying interface %s info with socket ioctls and ethtool...",
	      ifaddr->ifa_name);

#ifdef __linux__
	/* identify the target interface for following socket ioctls */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifaddr->ifa_name, IFNAMSIZ);

	/* try to get the MTU, and see if the device exists */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		goto out;
	}
	if (ioctl(sockfd, SIOCGIFMTU, &ifr) < 0) {
		assert(errno == ENODEV);
		goto out_with_sockfd;
	}
	/* set MSS = MTU for now, the caller will remove the header size */
	CCI_VALGRIND_MEMORY_MAKE_READABLE(&ifr.ifr_mtu, sizeof(ifr.ifr_mtu));
	device->max_send_size = ifr.ifr_mtu;

	/* try to get the link rate now, kernel allows non-root since 2.6.37 only */
	ecmd.cmd = ETHTOOL_GSET;
	ifr.ifr_data = (void *)&ecmd;
	if (ioctl(sockfd, SIOCETHTOOL, &ifr) < 0) {
		if (errno == EPERM) {
			debug(CCI_DB_INFO,
			      " ethtool get settings returned EPERM, falling back to custom ioctl");
			goto out_with_sockfd;
		}
		if (errno != ENODEV && errno != EOPNOTSUPP) {
			perror("SIOCETHTOOL ETHTOOL_GSET");
			goto out_with_sockfd;
		}
		/* we won't get link rate anyhow */
		debug(CCI_DB_INFO,
		      " ethtool get settings not supported, cannot retrieve link rate");
	} else {
		unsigned speed;
		CCI_VALGRIND_MEMORY_MAKE_READABLE(&ecmd, sizeof(ecmd));
#if HAVE_DECL_ETHTOOL_CMD_SPEED
		speed = ethtool_cmd_speed(&ecmd);
#else
		speed = ecmd.speed;
#endif
		device->rate = speed == -1 ? 0 : speed * 1000000ULL;
	}

	/* try to get the bus id now */
	edi.cmd = ETHTOOL_GDRVINFO;
	ifr.ifr_data = (void *)&edi;
	if (ioctl(sockfd, SIOCETHTOOL, &ifr) < 0) {
		if (errno != ENODEV && errno != EOPNOTSUPP) {
			perror("SIOCETHTOOL ETHTOOL_GDRVINFO");
			goto out_with_sockfd;
		}
		/* we won't get bus info anyhow */
		debug(CCI_DB_INFO,
		      " ethtool get drvinfo not supported, cannot retrieve pci id");
	} else {
		/* try to parse. if it fails, the device is not pci */
		CCI_VALGRIND_MEMORY_MAKE_READABLE(&edi, sizeof(edi));
		sscanf(edi.bus_info, "%04x:%02x:%02x.%01x",
		       &device->pci.domain, &device->pci.bus, &device->pci.dev,
		       &device->pci.func);
	}

	close(sockfd);
#endif /* __linux__ */

	return 0;

out_with_sockfd:
	close(sockfd);
out:
	return -1;
}
#endif

int cci__parse_config(const char *path)
{
	int ret = 0, i = 0, arg_cnt = 0, transport = 0, is_default = 0;
	char buffer[CCI_BUF_LEN], *str, *default_name = NULL;
	FILE *file;
	struct cci_device *d = NULL;
	cci__dev_t *dev = NULL;

	file = fopen(path, "r");
	if (!file) {
		cci__free_configfile_devs(NULL);
		return errno;
	}

	while (1) {
		int len;
		char *hash, *open, *close, *equal;
		char key[CCI_MAX_KEY_LEN], value[CCI_MAX_VALUE_LEN];

		str = fgets(buffer, CCI_BUF_LEN, file);
		if (str == NULL) {
			if (errno == EINTR)
				continue;
			else
				break;
		}

		/* skip empty lines */
		if ((len = strlen(buffer)) == 0)
			continue;

		/* skip newlines */
		if (1 == len && (strcmp(buffer, "\n") == 0))
			continue;

		/* ignore anything after # */
		hash = strchr(buffer, '#');
		if (hash == buffer)	/* skip comment lines */
			continue;
		else if (hash)
			*hash = '\0';

		/* check for new device "[foo]" */
		open = strchr(buffer, '[');
		close = strchr(buffer, ']');
		if (open && close && (uintptr_t) open < (uintptr_t) close) {

			if (d) {
				if (arg_cnt < CCI_MAX_ARGS) {
					/* release the unused pointers */
					d->conf_argv =
					    realloc((char **) d->conf_argv,
						    sizeof(char *) * (arg_cnt +
								      1));
				}
				if (transport == 1) {
					TAILQ_INSERT_TAIL(&globals->configfile_devs, dev, entry);
					debug(CCI_DB_DRVR,
					      "read device [%s] (transport %s) from config file",
					      d->name, d->transport);
					i++;
				} else {
					/* device does not have a transport, free it */
					debug(CCI_DB_WARN,
					      "device [%s] does not have a transport. Freeing it.",
					      d->name);
					cci__free_dev(dev);
				}
				d = NULL;
				dev = NULL;
			}

			if (i == CCI_MAX_DEVICES) {
				debug(CCI_DB_WARN,
				      "too many devices in CCI_CONFIG file");
				break;
			}

			if ((uintptr_t) close < (uintptr_t) open + 2) {
				debug(CCI_DB_WARN,
				      "invalid device name \"%s\".", buffer);
				continue;
			}

			/* new device found */

			dev = calloc(1, sizeof(*dev));
			if (!dev) {
				debug(CCI_DB_WARN,
				      "calloc failed for device %s", open);
				return cci__free_configfile_devs(NULL);
			}
			cci__init_dev(dev);

			d = &dev->device;
			d->conf_argv = calloc(CCI_MAX_ARGS + 1, sizeof(char *));
			if (!d->conf_argv) {
				debug(CCI_DB_WARN,
				      "calloc failed for device %s conf_argv",
				      open);
				cci__free_dev(dev);
				return cci__free_configfile_devs(NULL);
			}

			arg_cnt = 0;
			transport = 0;
			open++;
			*close = '\0';
			d->name = strdup(open);
			if (!d->name) {
				cci__free_dev(dev);
				return cci__free_configfile_devs(NULL);
			}
			continue;
		}

		/* look for key = value */
		equal = strchr(buffer, '=');
		if (!equal)
			continue;

		ret = sscanf(buffer, "%s = %s", key, value);
		if (ret != 2) {
			if (ret == 1) {
				char *tmp;

				/* look for key=value in key */
				equal = strchr(key, '=');
				if (!equal)
					continue;
				tmp = equal + 1;
				if (*tmp == '\0')
					continue;
				*equal = '\0';
				sscanf(tmp, "%s", value);
			}
		}
		if (d) {
			if (arg_cnt < CCI_MAX_ARGS) {
				char arg[CCI_BUF_LEN];

				snprintf(arg, CCI_BUF_LEN, "%s=%s", key, value);
				((char **) d->conf_argv)[arg_cnt] = strdup(arg);
				if (!d->conf_argv[arg_cnt]) {
					cci__free_dev(dev);
					return cci__free_configfile_devs(NULL);
				}
				arg_cnt++;
				if (0 == strcmp(key, "transport")) {
					if (!transport) {
						d->transport = strdup(value);
						if (!d->transport) {
							cci__free_dev(dev);
							return cci__free_configfile_devs(NULL);
						}
						transport++;
					} else {
						debug(CCI_DB_WARN,
						      "device [%s] has more than one transport. Freeing it.",
						      d->name);
						cci__free_dev(dev);
						d = NULL;
						dev = NULL;
					}
				} else if (0 == strcmp(key, "priority")) {
					int priority = 0;

					priority = (int)strtol(value, NULL, 0);
					if (priority < 0 || priority > 100) {
						debug(CCI_DB_WARN,
						      "device [%s] has illegal value of %d. Ignoring it.",
						      d->name, priority);
						continue;
					}
					dev->priority = priority;
				} else if (0 == strcmp(key, "default")) {
					if (is_default != 0) {
						debug(CCI_DB_WARN,
						      "device [%s] has default set and device [%s] already set it. Ignoring it.",
						      d->name, default_name);
					}
					dev->is_default = 1;
					is_default = i;
					default_name = (char *)d->name;
				}
			} else {
				debug(CCI_DB_WARN,
				      "too many args for device [%s]", d->name);
			}
		}
	}
	if (d) {
		if (arg_cnt < CCI_MAX_ARGS) {
			/* release the unused pointers */
			d->conf_argv =
			    realloc((char **) d->conf_argv,
				    sizeof(char *) * (arg_cnt + 1));
		}
		if (transport == 1) {
			TAILQ_INSERT_TAIL(&globals->configfile_devs, dev, entry);
			debug(CCI_DB_DRVR,
			      "read device [%s] (transport %s) from config file",
			      d->name, d->transport);
			i++;
		} else {
			/* device does not have a transport, free it */
			debug(CCI_DB_WARN,
			      "device [%s] does not have a transport. Freeing it.",
			      d->name);
			cci__free_dev(dev);
		}
		d = NULL;
		dev = NULL;
	}

	fclose(file);

	return 0;
}

int cci_init(uint32_t abi_ver, uint32_t flags, uint32_t * caps)
{
	int ret;
	int i, j;

	cci__get_debug_env();

	if (abi_ver != CCI_ABI_VERSION) {
		debug(CCI_DB_INFO, "got ABI version %u, but expected %d",
		      abi_ver, CCI_ABI_VERSION);
		return CCI_EINVAL;
	}

	if (!caps)
		return CCI_EINVAL;

	pthread_mutex_lock(&init_lock);

	if (0 == initialized) {
		cci__dev_t *dev;
		char *str;

		/* init globals */

		globals = calloc(1, sizeof(*globals));
		if (!globals) {
			ret = CCI_ENOMEM;
			goto out;
		}

		globals->flags = flags;
		TAILQ_INIT(&globals->devs);
		globals->configfile = 0;
		TAILQ_INIT(&globals->configfile_devs);

		ret = pthread_mutex_init(&globals->lock, NULL);
		if (ret) {
			perror("pthread_mutex_init failed:");
			ret = errno;
			goto out_with_globals;
		}

		if (CCI_SUCCESS != (ret = cci_plugins_init())) {
			goto out_with_globals;
		}
		if (CCI_SUCCESS != (ret = cci_plugins_ctp_open())) {
			goto out_with_plugins_init;
		}
		if (NULL == cci_all_plugins
		    || NULL == cci_all_plugins[0].plugin) {
			ret = CCI_ERR_NOT_FOUND;
			goto out_with_plugins_ctp_open;
		}

		/* lock the device list while initializing CTPs and devices */
		pthread_mutex_lock(&globals->lock);

		str = getenv("CCI_CONFIG");
		if (str && str[0] != '\0') {
			ret = cci__parse_config(str);
			if (ret) {
				debug(CCI_DB_ERR, "unable to parse CCI_CONFIG file %s",
				      str);
				ret = CCI_ERROR;
				goto out_with_glock;
			}
			globals->configfile = 1;
		}

		for (i = 0, j = 0;
		     cci_all_plugins[i].plugin != NULL;
		     i++) {
			cci_plugin_ctp_t *plugin = (cci_plugin_ctp_t *) cci_all_plugins[i].plugin;
			ret = cci_all_plugins[i].init_status = plugin->init(plugin, abi_ver, flags, caps);
			if (!ret)
				j++;
		}
		/* return an error if all plugins init failed */
		if (!j) {
			perror("all plugins init failed:");
			ret = errno;
			goto out_with_config_file;
		}

		/* drop devices that weren't claimed by any transport,
		 * they didn't move from configfile_devs to devs */
		cci__free_configfile_devs("not claimed by any transport");

		/* build devices array and list it */
		i=0;
		TAILQ_FOREACH(dev, &globals->devs, entry)
			i++;
		globals->devices = calloc(i + 1, sizeof(*globals->devices));
		if (!globals->devices) {
			ret = CCI_ENOMEM;
			goto out_with_plugins;
		}
		globals->devices[i] = NULL;
		i=0;

		/* list ready devices */
		TAILQ_FOREACH(dev, &globals->devs, entry) {
			debug(CCI_DB_DRVR,
			      "device [%s] (transport %s, default %d, priority %d, up %d) is ready",
			      dev->device.name, dev->device.transport,
			      dev->is_default, dev->priority, dev->device.up);
			globals->devices[i++] = &dev->device;
		}

		pthread_mutex_unlock(&globals->lock);

		/* success */
		initialized++;

	} else {
		/* already initialized */
		if (flags == globals->flags) {
			/* same parameters, no-op */
			initialized++;
		} else {
			/* TODO */
			/* if different, can we accomodate new params?
			 *    if yes, do so and return SUCCESS
			 *    if not, ignore and return CCI_ERROR
			 */
			ret = CCI_ERR_NOT_IMPLEMENTED;
			goto out;
		}
	}

	pthread_mutex_unlock(&init_lock);
	return CCI_SUCCESS;

out_with_plugins:
	for (i = 0;
             cci_all_plugins[i].plugin != NULL;
             i++) {
		cci_plugin_ctp_t *plugin = (cci_plugin_ctp_t *) cci_all_plugins[i].plugin;
		if (CCI_SUCCESS == cci_all_plugins[i].init_status)
			plugin->finalize(plugin);
	}
out_with_config_file:
	/* FIXME? */
out_with_glock:
	pthread_mutex_unlock(&globals->lock);
out_with_plugins_ctp_open:
	cci_plugins_ctp_close();
out_with_plugins_init:
	cci_plugins_finalize();
out_with_globals:
	free(globals);
out:
	pthread_mutex_unlock(&init_lock);
	return ret;
}
