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

#include "cci.h"
#include "cci_lib_types.h"
#include "plugins/base/public.h"
#include "plugins/core/core.h"
#include "plugins/core/base/public.h"
#include "cci-api.h"

int cci__debug = CCI_DB_DFLT;
cci__globals_t *globals = NULL;
int initialized = 0;

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

	if (dev->driver)
		free(dev->driver);

	/* TODO dev->priv */

	free(dev);

	return;
}

int cci__free_devs(void)
{
	cci__dev_t *dev;

	pthread_mutex_lock(&globals->lock);
	while (!TAILQ_EMPTY(&globals->devs)) {
		dev = TAILQ_FIRST(&globals->devs);
		TAILQ_REMOVE(&globals->devs, dev, entry);
		cci__free_dev(dev);
	}
	pthread_mutex_unlock(&globals->lock);

	return CCI_ENOMEM;
}

void cci__init_dev(cci__dev_t *dev)
{
	struct cci_device *device = &dev->device;

	dev->priority = 50; /* default */
	dev->is_default = 0;
	TAILQ_INIT(&dev->eps);
	pthread_mutex_init(&dev->lock, NULL);
	device->up = 1;
}

void cci__add_dev(cci__dev_t * dev)
{
	if (TAILQ_EMPTY(&globals->devs)) {
		/* insert at front */
		pthread_mutex_lock(&globals->lock);
		TAILQ_INSERT_HEAD(&globals->devs, dev, entry);
		pthread_mutex_unlock(&globals->lock);
	} else {
		int done = 0;
		cci__dev_t *dd;

		/* walk list and insert in order by priority */
		TAILQ_FOREACH(dd, &globals->devs, entry) {
			if (dev->priority > dd->priority) {
				pthread_mutex_lock(&globals->lock);
				TAILQ_INSERT_BEFORE(dd, dev, entry);
				pthread_mutex_unlock(&globals->lock);
				done = 1;
				break;
			}
		}
		if (!done) {
			pthread_mutex_lock(&globals->lock);
			TAILQ_INSERT_TAIL(&globals->devs, dev, entry);
			pthread_mutex_unlock(&globals->lock);
		}
	}
	return;
}

int cci__parse_config(const char *path)
{
	int ret = 0, i = 0, arg_cnt = 0, driver = 0, is_default = 0;
	char buffer[CCI_BUF_LEN], *str, *default_name = NULL;
	FILE *file;
	struct cci_device *d = NULL;
	cci__dev_t *dev = NULL;

	file = fopen(path, "r");
	if (!file) {
		cci__free_devs();
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
				if (driver == 1) {
					cci__add_dev(dev);
					debug(CCI_DB_DRVR,
					      "adding device [%s] (%d)",
					      d->name, i);
					i++;
				} else {
					/* device does not have a driver, free it */
					debug(CCI_DB_WARN,
					      "device [%s] does not have a driver. Freeing it.",
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
				return cci__free_devs();
			}
			cci__init_dev(dev);

			d = &dev->device;
			d->conf_argv = calloc(CCI_MAX_ARGS + 1, sizeof(char *));
			if (!d->conf_argv) {
				debug(CCI_DB_WARN,
				      "calloc failed for device %s conf_argv",
				      open);
				cci__free_dev(dev);
				return cci__free_devs();
			}

			arg_cnt = 0;
			driver = 0;
			open++;
			*close = '\0';
			d->name = strdup(open);
			if (!d->name) {
				cci__free_dev(dev);
				return cci__free_devs();
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
					return cci__free_devs();
				}
				arg_cnt++;
				if (0 == strcmp(key, "driver")) {
					if (!driver) {
						dev->driver = strdup(value);
						if (!dev->driver) {
							cci__free_dev(dev);
							return cci__free_devs();
						}
						driver++;
					} else {
						debug(CCI_DB_WARN,
						      "device [%s] has more than one driver. Freeing it.",
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
		if (driver == 1) {
			cci__add_dev(dev);
			debug(CCI_DB_DRVR, "adding device [%s] (%d)", d->name,
			      i);
			i++;
		} else {
			/* device does not have a driver, free it */
			debug(CCI_DB_WARN,
			      "device [%s] does not have a driver. Freeing it.",
			      d->name);
			cci__free_dev(dev);
		}
		d = NULL;
		dev = NULL;
	}

	fclose(file);

	/* free unused devices */
	if (i < CCI_MAX_DEVICES) {
		globals->devices = calloc(i + 1, sizeof(*globals->devices));
		if (!globals->devices) {
			cci__free_devs();
			free(globals);
		}
		globals->devices[i] = NULL;
	}

	i = 0;
	TAILQ_FOREACH(dev, &globals->devs, entry) {
		debug(CCI_DB_DRVR, "%d: %s", i, dev->device.name);
		globals->devices[i++] = &dev->device;
	}

	{
		/* dump config info */
		const char *conf;

		for (i = 0, d = globals->devices[0]; d != NULL;
		     i++, d = globals->devices[i]) {
			int j;

			debug(CCI_DB_DRVR, "[%s]", d->name);
			for (j = 0, conf = d->conf_argv[j];
			     conf != NULL; j++, conf = d->conf_argv[j]) {
				debug(CCI_DB_DRVR, "\t%s", conf);
			}
		}
	}

	return 0;
}

int cci_init(uint32_t abi_ver, uint32_t flags, uint32_t * caps)
{
	int ret;

	cci__get_debug_env();

	if (abi_ver != CCI_ABI_VERSION) {
		debug(CCI_DB_INFO, "got ABI version %u, but expected %d",
		      abi_ver, CCI_ABI_VERSION);
		return CCI_EINVAL;
	}

	if (!caps)
		return CCI_EINVAL;

	if (0 == initialized) {
		char *str;

		initialized++;

		/* init globals */

		globals = calloc(1, sizeof(*globals));
		if (!globals)
			return CCI_ENOMEM;

		TAILQ_INIT(&globals->devs);

		ret = pthread_mutex_init(&globals->lock, NULL);
		if (ret) {
			perror("pthread_mutex_init failed:");
			return errno;
		}

		if (CCI_SUCCESS != (ret = cci_plugins_init())) {
			return ret;
		}
		if (CCI_SUCCESS != (ret = cci_plugins_core_open())) {
			return ret;
		}
		if (NULL == cci_core) {
			return CCI_ERR_NOT_FOUND;
		}

		str = getenv("CCI_CONFIG");
		if (str && str[0] != '\0') {
			ret = cci__parse_config(str);
			if (ret) {
				debug(CCI_DB_ERR, "unable to parse CCI_CONFIG file %s",
				      str);
				return CCI_ERROR;
			}
			globals->configfile = 1;
		}

		ret = cci_core->init(abi_ver, flags, caps);
		if (ret) {
			perror("cci_core->init failed:");
			return errno;
		}
	} else {
		/* TODO */
		/* check parameters */
		/* if same, this is a no-op and return SUCCESS */
		/* if different, can we accomodate new params?
		 *    if yes, do so and return SUCCESS
		 *    if not, ignore and return CCI_ERROR
		 */
		return CCI_ERR_NOT_IMPLEMENTED;
	}

	return CCI_SUCCESS;
}
