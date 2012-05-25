/*
 * cci_check.c
 *
 * test implementation of cci
 *
 * int cci_init(uint32_t abi_ver, uint32_t flags, uint32_t caps);
 *
 * Author: Lawrence MacIntyre
 * 
 * History
 * 2012 Feb 9 : lpm : initial implementation
 * 2012 Feb 10 : lpm : added getopt_long, logfile, xml log
 * 2012 Feb 11 : lpm : added get_devices
 * 2012 Feb 23 : lpm : added create_endpoint
 */
 
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "cci_check.h"

#define ARGS "cfhlv:x"

/* Display program usage, and exit.
 */
void usage(const char* a) {
	fprintf(stderr, "usage: %s [--nofork] [--help] [--log[=<logfile name>]]\n", a);
	fprintf(stderr, "                 [--verbosity=<verbosity level>] [--xml[=<xml file name>]\n\n");
	fprintf(stderr, "                -f|--nofork - perform the tests in a single process\n");	
	fprintf(stderr, "                   default = fork each test\n");
	fprintf(stderr, "                -h|--help - print this text\n");
	fprintf(stderr, "                -l|--log[= <logfile name>] - create a logfile\n");	
	fprintf(stderr, "                   default = regressions/cci_check.log\n");
	fprintf(stderr, "                -v=<verbosity-level>|--verbosity=<verbosity-level>\n");	
	fprintf(stderr, "                   default=normal \n");
	fprintf(stderr, "                   possible levels are silent, minimal, normal, and verbose\n");	
	fprintf(stderr, "                -x|--xml[= <xml file name>] - create an xml logfile \n");	
	fprintf(stderr, "                   default = regressions/cci_check.xml\n");	
}

int main(int argc, char* argv[]) {
	uint32_t number_failed = 0;
	Suite *s = NULL;
	SRunner* sr = NULL;
	
	int32_t c = 0;
	int32_t longIndex = 0;
	extern char* optarg;
	
	char* nextWordPtr;
	char* lastWordPtr;

	char* logFile = "regressions/cci_check.log";
	bool createLog = false;
	bool freeLogFile = false;
	
	char* xmlLogFile = "regressions/cci_check.xml";
	bool createXML = false;
	bool freeXML = false;
	
  int status;
	struct stat statBuf;
	
  char* configFile;
  bool freeConfigFile = false;
  char* envVal = NULL;
  
	/* initialize input parameters */
	uint32_t outputVerbosity=CK_ENV;
	uint32_t forkStatus=CK_FORK;
	
	const struct option longOpts[] = {
		{"configfile", required_argument, NULL, 'c'},
		{"help", no_argument, NULL, 'h'},
		{"log", optional_argument, NULL, 'l'},
		{"nofork", no_argument, NULL, 'f'},
		{"verbosity", required_argument, NULL, 'v'},
		{"xml", optional_argument, NULL, 'x'},
		{NULL, no_argument, NULL, 0}
	};

	/* Process the arguments with getopt_long(), then 
	 * populate globalArgs. 
	 */

	nextWordPtr = strtok(argv[0],"/"); // split using slash as divider
	lastWordPtr = nextWordPtr;
	while (nextWordPtr != NULL) {
		lastWordPtr = nextWordPtr;
		nextWordPtr = strtok(NULL,"/");
	}

	while((c = getopt_long(argc, argv, ARGS, longOpts, &longIndex)) != -1) {
		switch(c) {
			case 'c':
        configFile = strdup(optarg);
        freeConfigFile = true;
				printf("configfile = %s requested\n", configFile);

				status = setenv("CCI_CONFIG", configFile, (int) 1);
				if(status != 0) {
					perror("setenv:");
					return 1;
				}
  
			break;
				
			case 'f':
				printf("NoFork requested.\n");
				forkStatus = CK_NOFORK;
				break;
				
			case 'h':
				usage(lastWordPtr);
				return 1;
			
			case 'l':
				createLog = true;
				if(optarg != NULL) {
					logFile = strdup(optarg);
					freeLogFile = true;
				}
				printf("Logfile = %s requested\n", logFile);
				break;
				
			case 'v':
				printf("Verbosity = %s requested\n", optarg);
				if(strcmp(optarg, "silent") == 0) {
					outputVerbosity = CK_SILENT;
				} else if(strcmp(optarg, "minimal") == 0) {
					outputVerbosity = CK_MINIMAL;
				} else if(strcmp(optarg, "normal") == 0) {
					outputVerbosity = CK_NORMAL;
				} else if(strcmp(optarg, "verbose") == 0) {
					outputVerbosity = CK_VERBOSE;
				} else {
					usage(lastWordPtr);
					return 1;
				}
				break;

			case 'x':
				createXML = true;
				if(optarg != NULL) {
					xmlLogFile = strdup(optarg);
					freeXML = true;
				}
				printf("XMLfile = %s requested\n", logFile);
				break;
				
			default:
				printf("default...\n");
				usage(lastWordPtr);
				return 1;
		}
	}
	
  envVal = getenv("CCI_CONFIG");
	if(envVal == NULL) {
		fprintf(stderr, "CCI_CONFIG environment variable is not defined.\n");
		return 1;
	} else if(strlen(envVal) == 0) {
		fprintf(stderr, "CCI_CONFIG is defined, but has zero length.\n");
		return 1;
	} else {
		printf("CCI_CONFIG value is %s\n", envVal);
  }
	
	status = stat(envVal, &statBuf);
	if(status != 0) {
		fprintf(stderr, "%s is either non-existent or you don't have permission to access it.\n", envVal);
		return 1;
	}
	
	s = cci_init_suite();
	if(s == NULL) {
		perror("cci_init_suite");
		return errno;
	}
	
	sr = srunner_create(s);
	if(sr == NULL) {
		perror("srunner_create");
		return errno;
	}

	srunner_set_fork_status (sr, forkStatus);
	
	if(createLog) {
		srunner_set_log(sr, logFile);
	}
	
	if(createXML) {
		srunner_set_xml(sr, xmlLogFile);
	}
	
	s = cci_strerror_suite();
	if(s == NULL) {
		perror("cci_strerror_suite");
		return errno;
	}	
	srunner_add_suite(sr, s);

	s = cci_get_devices_suite();
	if(s == NULL) {
		perror("cci_get_devices_suite");
		return errno;
	}	
	srunner_add_suite(sr, s);

	s = cci_create_endpoint_suite();
	if(s == NULL) {
		perror("cci_create_endpoint_suite");
		return errno;
	}	
	srunner_add_suite(sr, s);
  
 s = cci_get_opt_suite();
	if(s == NULL) {
		perror("cci_get_opt_suite");
		return errno;
	}	
	srunner_add_suite(sr, s);
  
  s = cci_set_opt_suite();
	if(s == NULL) {
		perror("cci_set_opt_suite");
		return errno;
	}	
	srunner_add_suite(sr, s);
  
	srunner_run_all (sr, outputVerbosity);	/* Same as CK_NORMAL + can be changed with environment variable CK_VERBOSITY */
																														/* CK_Verbosity = silent, minimal, normal, or verbose */
	
	number_failed = srunner_ntests_failed(sr);
	
	srunner_free(sr);
	
	if(freeLogFile) {
		free(logFile);
	}
	
	if(freeXML) {
		free(xmlLogFile);
	}
	
  if(freeConfigFile) {
    free(configFile);
  }
  
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}