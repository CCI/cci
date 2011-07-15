/* This is where the private functions are prototyped. */

void cci__free_dev(cci__dev_t *dev);

void cci__free_args(char **args);

int cci__free_devs(void);

void cci__add_dev(cci__dev_t *dev);

int cci__parse_config(const char *path);
