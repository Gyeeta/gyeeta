
// Uncomment the below line to ignore colorprints
/*#define 		GY_NO_ANSI_COLORS*/

#include 		"gy_common_inc.h"
#include 		"gy_print_offload.h"
#include 		"gy_statistics.h"

#include 		<thread>

int handle_signal(int signo)
{
	alarm(0);

	NOTEUNLOCKPRINT_OFFLOAD("Testing Offload printing from within a signal handler Current time = %ld ...\n", time(nullptr));
	return signo;
}	


int test_init_prints()
{
	int		ret;

	const char * 	pextraprint = "Extra Offload Print------------";

	IRPRINT("\n\n---------------Starting Initial Tests...-------------------\n\n");
	INFOPRINT("Normal INFOPRINT without color : Current time is %ld\n", time(nullptr));
	INFOPRINTCOLOR(GY_COLOR_GREEN, "INFOPRINT with color : Current time is %ld\n", time(nullptr));
	INFOPRINTCOLOR(GY_COLOR_CYAN, "Normal INFOPRINT with color and no newline : Current time is %ld", time(nullptr));

	NOTEPRINT("Normal NOTEPRINT without color : Current time is %ld\n", time(nullptr));
	NOTEPRINTCOLOR(GY_COLOR_GREEN, "NOTEPRINT with color : Current time is %ld\n", time(nullptr));

	WARNPRINT("Normal WARNPRINT without color : Current time is %ld\n", time(nullptr));
	WARNPRINTCOLOR(GY_COLOR_GREEN, "WARNPRINT with color : Current time is %ld\n", time(nullptr));

	ERRORPRINT("Normal ERRORPRINT without color : Ignore this error : Current time is %ld\n", time(nullptr));
	ERRORPRINTCOLOR(GY_COLOR_GREEN, "ERRORPRINT with color : Ignore this error : Current time is %ld\n", time(nullptr));

	errno = ENOSPC;
	PERRORPRINT("Testing PERRORPRINT without color : Ignore this error");
	errno = ENOSPC;
	PERRORPRINTCOLOR(GY_COLOR_RED, "Testing PERRORPRINT with color : Ignore this error");

	IRPRINTCOLOR(GY_COLOR_BOLD_GREEN, "\n\n\t\tTesting IRPRINTCOLOR...\n\n");
	IRPRINTCOLOR(GY_COLOR_BOLD_GREEN, "\n\n");
	INFOPRINTCOLOR(GY_COLOR_BLUE, "n");
	INFOPRINTCOLOR(GY_COLOR_BLUE, "n\n");

	ret = DEBUGPRINT("Starting Tests for Print offloads...\n\n");

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Color Info print using offload macro without offload initialization\n");

	gyeeta::set_stdout_buffer_mode(false);

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Unbuffered Color Info print using offload macro without offload initialization\n");

	CUSTOM_INFOPRINT(1, "Testing without init of Print Offload singleton\n");
	errno = ENOSPC;

	ret = CUSTOM_PERRORPRINT(2, "Testing dummy perror before Print Offload singleton init : Dummy write failed");

	ret = CUSTOM_PERRORUNLOCKPRINT(2, "Testing dummy unlock perror before Print Offload singleton init : Dummy write failed");

	ERRORPRINTCOLOR(GY_COLOR_RED, "Testing Normal error before singleton init...time = %ld\n", time(nullptr));

	ret = CUSTOM_ERRORUNLOCKPRINT(0, "Testing Normal unlock error before singleton init...time = %ld\n", time(nullptr));

	INFOPRINT("Another Test...");

	IRPRINT_OFFLOAD("Another Test using IRPRINT_OFFLOAD...");

	IRUNLOCKPRINT_OFFLOAD("Another Test using IRUNLOCKPRINT_OFFLOAD...\n");

	gyeeta::PRINT_OFFLOAD::init_singleton(5 /* Limit to 5/sec */, 100'000);
	
	gyeeta::PRINT_OFFLOAD::get_singleton()->set_default_custom_handler(
		[](gyeeta::PRINT_ELEM_C *pelem, char *printbuf, const char *time_buf, void *arg1, void *arg2)
		{
			const char			*pextra = (const char *)arg1;

			if (pelem->cust_type_ > 2) {
				INFOPRINTCOLOR(GY_COLOR_GREEN, "Received Offloaded msg of length %u with extra print : %s : Msg [%s.%06lu] : %s\n", 
						pelem->msglen_, pextra, time_buf, pelem->tv_.tv_usec, printbuf);
			}	
		}, (void *)pextraprint);

	for (int i = 0; i < 10; i++) {
		CUSTOM_INFOPRINT(i, "Testing rate limit and custom handler %d\n", i);
	}	

	ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "This error should be printed even though the rate limit has been breached...\n");

	gyeeta::gy_nanosleep(1, 0);

	gyeeta::PRINT_OFFLOAD::get_singleton()->set_rate_limit(1000);

	INFOPRINT_OFFLOAD("This message will be printed by a separate thread i = %d\n", errno);

	errno = ENOSPC;

	gyeeta::PRINT_OFFLOAD::get_singleton()->send_print_msg(gyeeta::MSG_TYPE_PERROR, 3, 
			[](gyeeta::PRINT_ELEM_C *pelem, char *printbuf, const char *time_buf, void *arg1, void *arg2)
			{
				INFOPRINTCOLOR(GY_COLOR_CYAN, "Direct Offload Handling with custom handler : Msg %s\n", printbuf);
			}, 	
		nullptr, nullptr, false, false, false, 
		"Testing dummy perror after Print Offload singleton init : Dummy write %d failed", 2);

	OFFLOADPRINT(gyeeta::MSG_TYPE_NO_LOG, 3, false, "Testing No Direct Logging. Just Logging with Custom Handler time = %ld ...", time(nullptr));

	PERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Using PERRORPRINTCOLOR_OFFLOAD : Dummy write failed %s", "testing..");
	
	char		buf1[10 * 1024];

	std::memset(buf1, ' ', sizeof(buf1) - 1);
	buf1[sizeof(buf1) - 1] = '\0';

	errno = ENOSPC;

	ret = PERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Testing a long.... print message of length 10 KB....%.*s", (int)sizeof(buf1) - 1, buf1);
	
	DEBUGPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "---Previous Long message was truncated to size %d : Original message was 10 KB ...\n", ret);

	NOTEPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Now testing Async safe offloading from within a signal handler : Sending a SIGINT signal...\n");

	kill(0, SIGINT);

	NOTEPRINTCOLOR_OFFLOAD(GY_COLOR_YELLOW, "Testing Message after signal has been delivered...\n");

	INFOPRINTCOLOR(GY_COLOR_BLUE, "All messages sent by this thread. Subsequent prints are by the offload thread...\n\n");

	gyeeta::gy_nanosleep(1, 0);

	return 0;
}


void func1(uint64_t *ptotalnsec)
{
	gyeeta::gy_msecsleep(1000);

	gyeeta::BENCH_HISTOGRAM		hist(0);
	
	GY_CC_BARRIER();

	uint64_t		startnsec = gyeeta::get_nsec_clock(), tnsec = startnsec, tnsec2;

	GY_CC_BARRIER();

	for (ssize_t i = 0; i < 100'000; ++i) {
		OFFLOADPRINT(gyeeta::MSG_TYPE_NO_LOG, 3, false, 
			"Testing No Direct Logging. Just Logging with Custom Handler Current iter = %ld sample string is %s\n", i, "A small sample string...");
		
		tnsec2 = gyeeta::get_nsec_clock();

		hist.add_data(tnsec2 - tnsec, 0);
		tnsec = tnsec2;
	}

	GY_CC_BARRIER();

	*ptotalnsec = gyeeta::get_nsec_clock() - startnsec;
}

static void benchmark_tests(size_t nthreads)
{
	std::vector<std::thread>	thrvec;
	uint64_t			*ptimevec;

	INFOPRINTCOLOR(GY_COLOR_BLUE, "Starting Benchmarking of 100'000 CUSTOM_INFOPRINT with %lu threads...\n", nthreads);

	ptimevec = new uint64_t[nthreads];
		
	for (size_t i = 0; i < nthreads; ++i) {	
		thrvec.emplace_back(func1, ptimevec + i);
	}

	for (size_t i = 0; i < nthreads; ++i) {	
		thrvec[i].join();
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Thread %lu : Time to execute 100'000 CUSTOM_INFOPRINTs : %lu nsec : Avg %lu nsec\n\n", i, ptimevec[i], ptimevec[i]/100'000);
	}

	delete [] ptimevec;
}	

int main(int argc, char **argv)
{
	gyeeta::gdebugexecn = 10;
	
	if (argc > 1) {
		gyeeta::guse_utc_time = true;
	}	

	gyeeta::GY_SIGNAL_HANDLER::init_singleton(argv[0], handle_signal, false);

	test_init_prints();

	try {
		IRPRINT("\n\n------------------------------------------------------\n\n");

		int		fdout = open("/dev/null", O_WRONLY);

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Now benchamrking time for 100'000 CUSTOM_INFOPRINT() with sink writing to /dev/null...\n\n");

		gyeeta::PRINT_OFFLOAD::get_singleton()->set_default_custom_handler(
			[](gyeeta::PRINT_ELEM_C *pelem, char *printbuf, const char *time_buf, void *arg1, void *arg2)
			{
				int		fdout = (int)(intptr_t)arg1;

				IRFDPRINT(fdout, "Received Log Msg [%s.%06lu] : %s\n", time_buf, pelem->tv_.tv_usec, printbuf);
			}, (void *)(intptr_t)fdout);
		
		gyeeta::PRINT_OFFLOAD::get_singleton()->set_rate_limit(0);

		benchmark_tests(1);

		gyeeta::gy_msecsleep(5000);
		gyeeta::PRINT_OFFLOAD::get_singleton()->print_stats(true);

		benchmark_tests(4);

		gyeeta::gy_msecsleep(5000);
		gyeeta::PRINT_OFFLOAD::get_singleton()->print_stats(true);

		close(fdout);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while benchmarking...%s\n\n", GY_GET_EXCEPT_STRING);
	);

	gyeeta::PRINT_OFFLOAD::get_singleton()->~PRINT_OFFLOAD();

	free(gyeeta::PRINT_OFFLOAD::get_singleton());

	return 0;
}

