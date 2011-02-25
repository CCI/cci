/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>
#include <string.h>

#include "cci.h"
#include "cci_lib_types.h"
#include "plugins/base/public.h"
#include "plugins/core/core.h"
#include "plugins/core/base/public.h"

cci__globals_t *globals = NULL;

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

void cci__free_dev(cci__dev_t *dev)
{
    cci_device_t *device;

    if (!dev)
        return;

    device = &dev->device;

    if (device->name)
        free((char *) device->name);

    if (device->info)
        free((char *) device->info);

    cci__free_args((char **) device->conf_argv);

    if (dev->driver)
        free(dev->driver);

    /* TODO dev->priv */
    /* TODO dev->leps */

    free(dev);

    return;
}

int cci__free_devs(void) {
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

void cci__add_dev(cci__dev_t *dev)
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
    char buffer[CCI_BUF_LEN], *str, *default_name;
    FILE *file;
    cci_device_t *d = NULL;
    cci__dev_t  *dev = NULL;

    file = fopen(path, "r");
    if (!file) {
        cci__free_devs();
        return errno;
    }

    while (1) {
        int     len;
        char    *hash, *open, *close, *equal;
        char    key[CCI_MAX_KEY_LEN], value[CCI_MAX_VALUE_LEN];

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
        if (hash == buffer)     /* skip comment lines */
            continue;
        else if (hash)
            *hash = '\0';

        /* check for new device "[foo]" */
        open = strchr(buffer, '[');
        close = strchr(buffer, ']');
        if (open && close &&
            (uintptr_t) open < (uintptr_t) close) {

            if (d) {
                if (arg_cnt < CCI_MAX_ARGS) {
                    /* release the unused pointers */
                    d->conf_argv = realloc(d->conf_argv, sizeof(char *) * (arg_cnt + 1));
                }
                if (driver == 1) {
                    cci__add_dev(dev);
                    fprintf(stderr, "adding device [%s] (%d)\n", d->name, i);
                    i++;
                } else {
                    /* device does not have a driver, free it */
                    fprintf(stderr, "device [%s] does not have a driver. Freeing it.\n",
                            d->name);
                    cci__free_dev(dev);
                }
                d = NULL;
                dev = NULL;
            }

            if (i == CCI_MAX_DEVICES) {
                fprintf(stderr, "too many devices in CCI_CONFIG file\n");
                break;
            }

            if ((uintptr_t) close < (uintptr_t) open + 2) {
                fprintf(stderr, "invalid device name \"%s\".\n", buffer);
                continue;
            }

            /* new device found */

            dev = calloc(1, sizeof(*dev));
            if (!dev) {
                fprintf(stderr, "calloc failed for device %s\n", open);
                return cci__free_devs();
            }
            dev->priority = 50; /* default */
            /* dev->is_default = 0; */
            TAILQ_INIT(&dev->eps);
            TAILQ_INIT(&dev->leps);
            pthread_mutex_init(&dev->lock, NULL);

            d = &dev->device;
            d->conf_argv = calloc(CCI_MAX_ARGS + 1, sizeof(char *));
            if (!d->conf_argv) {
                fprintf(stderr, "calloc failed for device %s conf_argv\n", open);
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
                d->conf_argv[arg_cnt] = strdup(arg);
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
                        fprintf(stderr, "device [%s] has more than one driver. Freeing it.\n",
                                d->name);
                        cci__free_dev(dev);
                        d = NULL;
                        dev = NULL;
                    }
                } else if (0 == strcmp(key, "priority")) {
                    int priority = 0;

                    priority = (int) strtol(value, NULL, 0);
                    if (priority < 0 || priority > 100) {
                        fprintf(stderr, "device [%s] has illegal value of %d. Ignoring it.\n",
                                d->name, priority);
                        continue;
                    }
                    dev->priority = priority;
                } else if (0 == strcmp(key, "default")) {
                    if (is_default != 0) {
                        fprintf(stderr, "device [%s] has default set and device [%s] already set it. Ignoring it.\n", d->name, default_name);
                    }
                    dev->is_default = 1;
                    is_default = i;
                    default_name = (char *) d->name;
                }
            } else {
                fprintf(stderr, "too many args for device [%s]\n",
                                d->name);
            }
        }
    }
    if (d) {
        if (arg_cnt < CCI_MAX_ARGS) {
            /* release the unused pointers */
            d->conf_argv = realloc(d->conf_argv, sizeof(char *) * (arg_cnt + 1));
        }
        if (driver == 1) {
            cci__add_dev(dev);
            fprintf(stderr, "adding device [%s] (%d)\n", d->name, i);
            i++;
        } else {
            /* device does not have a driver, free it */
            fprintf(stderr, "device [%s] does not have a driver. Freeing it.\n",
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
        fprintf(stderr, "%d: %s\n", i, dev->device.name);
        globals->devices[i++] = &dev->device;
    }

    {
        /* dump config info */
        const char *conf;

        for (i = 0, d = globals->devices[0]; d != NULL; i++, d = globals->devices[i]) {
            int j;

            fprintf(stderr, "[%s]\n", d->name);
            for (j = 0, conf = d->conf_argv[j];
                 conf != NULL;
                 j++, conf = d->conf_argv[j]) {
                    fprintf(stderr, "\t%s\n", conf);
            }
        }
    }

    return 0;
}

int cci_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps)
{
    int ret;
    static int once = 0;

    if (abi_ver != CCI_ABI_VERSION) {
        fprintf(stderr, "cci_init: got ABI version %d, but expected %d\n",
                abi_ver, CCI_ABI_VERSION);
        return CCI_EINVAL;
    }

    if (0 == once) {
        char *str;

        once++;

        /* init globals */

        globals = calloc(1, sizeof(*globals));
        if (!globals)
            return CCI_ENOMEM;

        TAILQ_INIT(&globals->devs);
        TAILQ_INIT(&globals->svcs);

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
        if (!str || str[0] == '\0') {
            fprintf(stderr, "unable to find CCI_CONFIG environment "
                            "variable.\n");
            return CCI_ERR_NOT_FOUND;
        }

        ret = cci__parse_config(str);
        if (ret) {
            fprintf(stderr, "unable to parse CCI_CONFIG file %s\n", str);
            return CCI_ERROR;
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

