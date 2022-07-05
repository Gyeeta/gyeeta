
#include		"gy_common_inc.h"
#include 		"gy_libcurl.h"
#include		"gy_cloud_metadata.h"

using namespace 	gyeeta;

int main(int argc, char *argv[])
{
	gdebugexecn = 1;

	if (argc != 2) {
		IRPRINT("\n\nUsage : %s <Cloud Type e.g. aws/gcp/azure/on-prem>\n\n", argv[0]);
		exit(EXIT_FAILURE);
	}	
	
	GY_CURL_EASY::global_init();
	
	try {
		CLOUD_METADATA		meta(argv[1]);
	
	}
	GY_CATCH_EXPRESSION(
		ERRORPRINT("Failed to get Instance Metadata : %s\n\n", GY_GET_EXCEPT_STRING);
	);

	GY_CURL_EASY::global_cleanup();
}	




