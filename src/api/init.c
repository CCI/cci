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
#define CCI_MAX_DEVICES         32
#define CCI_MAX_ARGS            32
#define CCI_MAX_KEY_LEN         256
#define CCI_MAX_VALUE_LEN       512

int cci__free_devices(cci_device_t **devices)
{
    int i;
    cci_device_t *d = NULL;

    for (i = 0, d = devices[0]; d != NULL; i++, d = devices[i]) {
        if (d->conf_argv)
            free(d->conf_argv);
        free(d);
    }
    free(devices);

    return CCI_ENOMEM;
}

int cci__parse_config(const char *path)
{
    int ret = 0, i = 0, arg_cnt = 0;
    char buffer[CCI_BUF_LEN];
    FILE *file;
    cci__globals_t *g;
    cci_device_t **devices, *d = NULL;

    /* allocate the globals */
    g = calloc(1, sizeof(*g));
    if (!g)
        return CCI_ENOMEM;

    /* allocate device ptr array */
    devices = calloc(CCI_MAX_DEVICES + 1, sizeof(*devices));
    if (!devices) {
        free(g);
        return CCI_ENOMEM;
    }

    /* allocate device storage */
    for (i = 0; i < CCI_MAX_DEVICES + 1; i++) {
        devices[i] = calloc(1, sizeof(*d));
        if (!devices[i]) {
            free(g);
            return cci__free_devices(devices);
        }

        d = devices[i];
        d->conf_argv = calloc(CCI_MAX_ARGS + 1, sizeof(char *));
        if (!d->conf_argv) {
            free(g);
            return cci__free_devices(devices);
        }
    }

    file = fopen(path, "r");
    if (!file)
        return errno;

    i = 0;

    while((fgets(buffer, CCI_BUF_LEN, file)) != NULL) {
        int     len;
        char    *hash, *open, *close, *equal;
        char    key[CCI_MAX_KEY_LEN], value[CCI_MAX_VALUE_LEN];

        /* skip empty lines */
        if ((len = strlen(buffer)) == 0)
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
            if (d && arg_cnt < CCI_MAX_ARGS) {
                /* release the unused pointers */
                d->conf_argv = realloc(d->conf_argv, sizeof(char *) * arg_cnt);
            }
            if (i == CCI_MAX_DEVICES) {
                fprintf(stderr, "too many devices in CCI_CONFIG file\n");
                break;
            }
            d = devices[i];
            arg_cnt = 0;
            i++;
            open++;
            *close = '\0';
            d->name = strdup(open);
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
                arg_cnt++;
            } else {
                fprintf(stderr, "too many args for device [%s]\n",
                                d->name);
            }
        }
    }

    fclose(file);

    /* free unused devices */
    if (i < CCI_MAX_DEVICES) {
        int j;

        for (j = CCI_MAX_DEVICES; j >= i; j--) {
            free(devices[j]->conf_argv);
            devices[j]->conf_argv = NULL;
        }
        devices = realloc(devices, i * sizeof(*devices));
        devices[i] = NULL;
    }

    /* check that each device specifies a driver */
    for (i = 0, d = devices[0]; d != NULL; i++, d = devices[i]) {
        int j, driver;
        const char *conf;

        driver = 0;

        for (j = 0, conf = d->conf_argv[j];
             conf != NULL;
             j++, conf = d->conf_argv[j])
                if (memcmp(conf, "driver=", 7) == 0)
                    driver = 1;

        /* FIXME need to create a new array and copy the good devices only */
        if (!driver)
            printf("device [%s] does not have a driver\n", d->name);
    }

    {
        /* dump config info */
        const char *conf;

        for (i = 0, d = devices[0]; d != NULL; i++, d = devices[i]) {
            int j;

            printf("[%s]\n", d->name);
            for (j = 0, conf = d->conf_argv[j];
                 conf != NULL;
                 j++, conf = d->conf_argv[j]) {
                    printf("\t%s\n", conf);
            }
        }
    }

    g->devices = devices;
    globals = g;

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

        ret = pthread_mutex_init(&globals->lock, NULL);
        if (ret) {
            perror("pthread_mutex_init failed:");
            return errno;
        }

        TAILQ_INIT(&globals->svcs);
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

    return cci_core->init(abi_ver, flags, caps);
}

