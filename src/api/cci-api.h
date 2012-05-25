/* This is where the private functions are prototyped. */

void cci__free_dev(cci__dev_t * dev);

void cci__free_args(char **args);

void cci__add_dev(cci__dev_t * dev);

void cci__init_dev(cci__dev_t *dev);

int cci__parse_config(const char *path);

#ifdef HAVE_GETIFADDRS
#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif
int cci__get_dev_ifaddrs_info(cci__dev_t *dev, struct ifaddrs *ifaddr);
#endif
