/*
 * cci_get_devices.c
 *
 * test implementation of cci_get_devices() to ensure that it rejects invalid input.
 *
 * int cci_get_devices( cci_device_t const ***const devices );
 *
 * Author: Lawrence MacIntyre
 * 
 * History:
 * 2012 Feb 10 : lpm : initial implementation
 * 2012 Feb 22 : lpm : add comparison to input file data
 * 2012 Feb 23 : lpm : add get_devices_null
 * 2012 Apr 05 : lpm : fixed cci_strerror() for new format
 * 2012 Apr 05 : lpm : fixed cci_get_devices() for new format
 * 2012 Apr 05 : lpm : add check for zero-length CCI_CONFIG (export CCI_CONFIG=)
 */
 
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include "cci_check.h"
 
#define MAX_LINE_LENGTH 80

typedef struct {
	char* name;
	int index;
  bool count;
} deviceArray;

typedef struct {
	int32_t domain;
  int32_t bus;
	int32_t dev;
	int32_t func;
} PCIStruct;

typedef struct {
	char name[MAX_LINE_LENGTH];
	uint32_t maxSendSize;
	uint64_t rate;
	PCIStruct pci;
	char driver[MAX_LINE_LENGTH];
	char ip[MAX_LINE_LENGTH];
	char mtu[MAX_LINE_LENGTH];
} deviceStruct;

START_TEST (get_devices_correct) {
  uint32_t initFlags = 0;
  uint32_t capabilities = 0;
  uint32_t status = 0;
  int32_t i,j;
  cci_device_t const ** const devices = NULL;   		/* available device structure */
  cci_device_t const ** d = NULL;
	FILE* iFile;
	char line[MAX_LINE_LENGTH+1];
	char* lineP = line;
	void* rStatus;
	unsigned int lineLength;
	deviceStruct* devStruct;
	deviceStruct* devStructP;
  char* openBracket;
	char* closeBracket;
	char* equalP;
	uint32_t nameLength;
  char** keyval;
  char* iniFile;
	int deviceCount = 0;
	int checkDeviceCount = 0;
	deviceArray* devArray;
	deviceArray* devArrayP;
	bool begin = true;

  /* translate the environment variable */
  iniFile = getenv("CCI_CONFIG");
  fail_if(iniFile == NULL, "getenv(CCI_CONFIG) failed. Environment variable CCI_CONFIG is not defined.");
  fail_if(strlen(iniFile) == 0, "CCI_CONFIG is defined, but is empty.");
	
	/* parse the config file */
	iFile = fopen(iniFile, "r");
	fail_if(iFile == NULL, "fopen(CONFIG_FILE) failed with status %s", strerror(errno));

	/* First Count the devices */
	while((rStatus = fgets(lineP, MAX_LINE_LENGTH, iFile)) != NULL) {
		if(strnlen(lineP, MAX_LINE_LENGTH) > 1) {
			if((strchr(lineP, '[') != NULL) && (strchr(lineP, ']') != NULL)) {
				++checkDeviceCount;
			}
		}
	}
	rewind(iFile);
	
	/* Allocate an array to store the file */
	devStruct = (deviceStruct*) calloc(checkDeviceCount, sizeof(deviceStruct));
	fail_if(devStruct == NULL, "calloc(devStruct) failed with status %s", strerror(errno));
	
  /* Now store the file in our new array */
	devStructP = devStruct;
	while((rStatus = fgets(lineP, MAX_LINE_LENGTH, iFile)) != NULL) {
		lineLength = strnlen(lineP, MAX_LINE_LENGTH);
		if(lineLength > 1) {
			if(((openBracket = strchr(lineP, '[')) != NULL) && ((closeBracket = strchr(lineP, ']')) != NULL)) {
				if(begin) {
					begin = false;
				} else {
					++devStructP;
				}
				nameLength = (uint32_t) closeBracket - (uint32_t) openBracket - 1;
				strncpy(devStructP->name, openBracket+1, nameLength);
				devStructP->name[nameLength] = '\0';
				devStructP->pci.domain = -1;
				devStructP->pci.bus = -1;
				devStructP->pci.dev = -1;
				devStructP->pci.func = -1;
				devStructP->rate = 10000000000LLU;
			} else if(strstr(lineP, "driver") != NULL) {
				strncpy(devStructP->driver, lineP, MAX_LINE_LENGTH);
				devStructP->driver[strlen(devStructP->driver)-1] = '\0';
			} else if(strstr(lineP, "ip") != NULL) {
				strncpy(devStructP->ip, lineP, MAX_LINE_LENGTH);
				devStructP->ip[strlen(devStructP->ip)-1] = '\0';
			} else if(strstr(lineP, "mtu") != NULL) {
				strncpy(devStructP->mtu, lineP, MAX_LINE_LENGTH);
				devStructP->mtu[strlen(devStructP->mtu)-1] = '\0';
				equalP = strchr(lineP, '=');
				devStructP->maxSendSize = strtoul(++equalP, NULL, 10) - 48;
			}
		}
	}
		
	fclose(iFile);
	
  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) &devices);
  fail_unless(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));

	/* count the devices. */
	for(d = devices, i=0; *d != NULL ; ++d, ++i) {
		++deviceCount;
	}
	
	/* make sure the number of devices is correct */
	fail_if(deviceCount != checkDeviceCount, "cci_get_devices() returned the wrong # of devices (%d) instead of (%d).", deviceCount, checkDeviceCount);

  /* They switched the order:-(. Begin by allocating an array to track the arrays */
	devArray = (deviceArray*) calloc(checkDeviceCount, sizeof(deviceArray));
	fail_if(devArray == NULL, "calloc(devArray) failed with status %s", strerror(errno));

  /* ensure that there are no duplicates */
	for(i=0, devStructP=devStruct,devArrayP=devArray; i<deviceCount; ++i, ++devStructP, ++devArrayP) {
		devArrayP->name = strdup(devStructP->name);
		
		for(j=0,d = devices; *d != NULL ; ++d,++j) {
			if(strcmp((*d)->name, devArrayP->name) == 0) {
				devArrayP->index = j;
        ++(devArrayP->count);
			}
		}
	}

	for(i=0,devArrayP=devArray; i<checkDeviceCount; ++i,++devArrayP) {
    fail_if(devArrayP->count != 1, "device %d (%s) not found in device array.", devArrayP->index, devArrayP->name);
	}
  
	for(d=devices, devStructP=devStruct, devArrayP=devArray; *d != NULL ; ++d, ++devStructP, ++devArrayP) {
    fail_unless(strlen(devStructP->name) == strlen((*(devices+devArrayP->index))->name),
      "cci_get_devices() failed to return device %d name (%s) != (%s).", i,
      devStructP->name, (*(devices+devArrayP->index))->name);
    
    fail_unless(strcmp(devStructP->name, (*(devices+devArrayP->index))->name) == 0,
      "cci_get_devices() failed to return correct device %d name. (%s) != (%s)", i,
      devStructP->name, (*(devices+devArrayP->index))->name);
    
    fail_unless(devStructP->maxSendSize == (*(devices+devArrayP->index))->max_send_size,
      "cci_get_devices() failed to return correct device %d max_send_size %d != %d.", i,
      devStructP->maxSendSize, (*(devices+devArrayP->index))->max_send_size);

    fail_unless(devStructP->rate == (*(devices+devArrayP->index))->rate,
      "cci_get_devices() failed to return correct device %d rate %lld != %lld.", i,
      devStructP->rate, (*(devices+devArrayP->index))->rate);
    
    fail_unless(devStructP->pci.domain == (*(devices+devArrayP->index))->pci.domain,
      "cci_get_devices() failed to return correct device %d PCI domain %d != %d.", i,
      devStructP->pci.domain, (*(devices+devArrayP->index))->pci.domain);
    
    fail_unless(devStructP->pci.bus == (*(devices+devArrayP->index))->pci.bus,
      "cci_get_devices() failed to return correct device %d PCI bus %d != %d.", i,
      devStructP->pci.bus, (*(devices+devArrayP->index))->pci.bus);
    
    fail_unless(devStructP->pci.dev == (*(devices+devArrayP->index))->pci.dev,
      "cci_get_devices() failed to return correct device %d PCI dev %d != %d.", i,
      devStructP->pci.dev, (*(devices+devArrayP->index))->pci.dev);
    
    fail_unless(devStructP->pci.func == (*(devices+devArrayP->index))->pci.func,
      "cci_get_devices() failed to return correct device %d PCI func %d != %d.", i,
      devStructP->pci.func, (*(devices+devArrayP->index))->pci.func);

		for(keyval = (char**) (*(devices+devArrayP->index))->conf_argv; *keyval != NULL; keyval++) {
			if(strstr(*keyval, "driver") != NULL) {
				fail_unless(strlen(devStructP->driver) == strlen(*keyval),
					"cci_get_devices() failed to return correct device %d driver %d != %d.", i,
					strlen(devStructP->driver), strlen(*keyval));
    
				fail_unless(strncmp(devStructP->driver, *keyval, MAX_LINE_LENGTH) == 0,
					"cci_get_devices() failed to return correct device %d driver (%s) != (%s)", i,
					devStructP->driver, *keyval);
			}

			if(strstr(*keyval, "ip") != NULL) {
				fail_unless(strlen(devStructP->ip) == strlen(*keyval),
					"cci_get_devices() failed to return correct device %d ip %d != %d.", i,
					strlen(devStructP->ip), strlen(*keyval));
    
				fail_unless(strncmp(devStructP->ip, *keyval, MAX_LINE_LENGTH) == 0,
					"cci_get_devices() failed to return correct device %d MTU (%s) != (%s)", i,
					devStructP->ip, *keyval);
			}

			if(strstr(*keyval, "mtu") != NULL) {
				fail_unless(strncmp(devStructP->mtu, *keyval, MAX_LINE_LENGTH) == 0,
					"cci_get_devices() failed to return correct device %d MTU (%s) != (%s)", i,
					devStructP->mtu, *keyval);
			}
		}
	}
}
END_TEST

START_TEST (get_devices_null) {
  uint32_t initFlags = 0;
  uint32_t capabilities = 0;
  uint32_t status = 0;
	cci_device_t const ** const devices = NULL;   		/* available device structure */
 
  /* Initialize cci library */
  status = cci_init(CCI_ABI_VERSION, initFlags, &capabilities);
  fail_unless(status == CCI_SUCCESS, "cci_init() failed with status %s", cci_strerror(NULL, status));
	
  /* get a list of the available devices */
  status = cci_get_devices((cci_device_t * const **) devices);
  fail_if(status == CCI_SUCCESS, "cci_get_devices() failed with status %s", cci_strerror(NULL, status));
}
END_TEST

/* Now build the individual tests into a test suite */

Suite* cci_get_devices_suite(void) {
	Suite *s = NULL;
	TCase *tc = NULL;

	s = suite_create ("cci_get_devices");
	if(s == NULL) {
		perror("suite_create(cci_get_devices)");
		return NULL;
	}
	
	tc = tcase_create("get_devices_case");
	if(tc == NULL) {
		perror("tcase_create(get_devices_case)");
		return NULL;
	}
	
	tcase_add_test(tc, get_devices_correct);
	tcase_add_test_raise_signal(tc, get_devices_null, SIGSEGV);
	suite_add_tcase(s, tc);

	return s;
}