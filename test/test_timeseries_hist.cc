
#include		"gy_common_inc.h"
#include		"gy_file_api.h"
#include		"gy_file_api.h"
#include		"gy_pkt_pool.h"

#include 		<unistd.h>
#include 		<cstdlib>
#include 		<string>
#include		<cstdint>

#include 		"TimeseriesSlabHistogram.h"
#include 		"TimeseriesSlabHistogram-defs.h"
#include 		"folly/stats/TimeseriesHistogram.h"
#include 		"folly/stats/TimeseriesHistogram-defs.h"

#include		"gy_statistics.h"

#include 		<iostream>

using 			namespace folly;
using 			namespace gyeeta;
using 			std::chrono::seconds;

using CPU_HISTOGRAM	= PERCENT_TIME_HISTOGRAM<Level_5s_5min_5days_all, NULL_MUTEX>;

int test_gy_slab_resp(RESP_TIME_HISTOGRAM<SCOPE_GY_MUTEX> & slabhist)
{
	time_t				tnow = time(nullptr);
	char				buf1[4096];
	size_t				bucket_id;

	for (int i = 0; i < 99; i++) {
		slabhist.add_data(i, tnow, bucket_id);
	}	

	for (int i = 0; i < 5; i++) {
		slabhist.add_data(i + 1000, tnow, bucket_id);
	}	
	
	slabhist.flush(tnow);

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Initial Response Histogram : \n%s\n\n\n", slabhist.get_print_str(buf1, sizeof(buf1) - 1, 99));

	gy_nanosleep(1, 0);

	time_t		newtime = time(nullptr) + 3600;

	for (int i = 0; i < 100; i++) {
		slabhist.add_data(15 + i, newtime, bucket_id);
	}	

	for (int i = 0; i < 10; i++) {
		slabhist.add_data(15 + i * 1000, newtime, bucket_id);
	}	

	slabhist.add_data(52000, newtime, bucket_id);
	slabhist.add_data(0, newtime, bucket_id);
	slabhist.add_data(1, newtime, bucket_id);
	slabhist.add_data(110'000, newtime, bucket_id);

	slabhist.add_data(100, newtime - 1, bucket_id);

	slabhist.flush(newtime);

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Final Response Histogram : \n%s\n\n", slabhist.get_print_str(buf1, sizeof(buf1) - 1, 99));

	return 0; 

}	

int test_resp_using_cache(RESP_TIME_HISTOGRAM<SCOPE_GY_MUTEX> & slabhist)
{
	using RESP_CACHE		= TIME_HIST_CACHE<RESP_TIME_HISTOGRAM<SCOPE_GY_MUTEX>, RESP_TIME_HASH>;

	RESP_CACHE			resp_cache(&slabhist);
	time_t				tnow = time(nullptr);
	char				buf1[4096];
	size_t				bucket_id;

	for (int i = 0; i < 99; i++) {
		resp_cache.add_cache(i, bucket_id, tnow);
	}	

	for (int i = 0; i < 5; i++) {
		resp_cache.add_cache(i + 1000, bucket_id, tnow);
	}	
	
	resp_cache.flush_to_histogram();

	slabhist.flush(tnow);

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Initial Response Histogram from cache : \n%s\n\n\n", slabhist.get_print_str(buf1, sizeof(buf1) - 1, 99));

	gy_nanosleep(1, 0);

	time_t		newtime = time(nullptr) + 3600;

	for (int i = 0; i < 100; i++) {
		resp_cache.add_cache(15 + i, bucket_id, newtime);
	}	

	for (int i = 0; i < 10; i++) {
		resp_cache.add_cache(15 + i * 1000, bucket_id, newtime);
	}	

	resp_cache.add_cache(52000, bucket_id, newtime);
	resp_cache.add_cache(0, bucket_id, newtime);
	resp_cache.add_cache(1, bucket_id, newtime);
	resp_cache.add_cache(110'000, bucket_id, newtime);

	resp_cache.add_cache(100, bucket_id, newtime - 1);

	resp_cache.flush_to_histogram();

	slabhist.flush(newtime);

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Final Response Histogram from cache : \n%s\n\n", slabhist.get_print_str(buf1, sizeof(buf1) - 1, 99));

	return 0; 

}	


int test_gy_slab_cpu(CPU_HISTOGRAM & slabhist)
{
	time_t				tnow = time(nullptr) - 3600;
	char				buf1[4096];
	int				ret;
	size_t				bucket_id;

	for (int i = 0; i <= 100; i++) {
		slabhist.add_data(i, tnow, bucket_id);
	}	
	slabhist.flush(tnow);

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Initial CPU Histogram : \n%s\n\n\n", slabhist.get_print_str(buf1, sizeof(buf1) - 1, 99));

	gy_nanosleep(1, 0);

	time_t		newtime = tnow + 1800;

	for (int i = 0; i < 5; i++) {
		for (int j = 0; j < 10; j++) 
			slabhist.add_data(80 + i, newtime, bucket_id);
	}	
	
	newtime = tnow + 3600;

	for (int i = 0; i < 5; i++) {
		for (int j = 0; j < 1000; j++) 
			slabhist.add_data(i, newtime, bucket_id);
	}	
	

	for (int i = 0; i < 100; i++) {
		slabhist.add_data(i, newtime, bucket_id);
	}	

	for (int i = 0; i < 10; i++) {
		slabhist.add_data(99, newtime, bucket_id);
	}	

	slabhist.add_data(-1, newtime, bucket_id);
	slabhist.add_data(0, newtime, bucket_id);
	slabhist.add_data(1, newtime, bucket_id);
	slabhist.add_data(100, newtime, bucket_id);

	slabhist.flush(newtime);

	std::decay_t<decltype(slabhist)>	copyslab(slabhist);

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Final CPU Histogram : \n%s\n\n", slabhist.get_print_str(buf1, sizeof(buf1) - 1, 99));

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Final Copy of CPU Histogram : \n%s\n\n", copyslab.get_print_str(buf1, sizeof(buf1) - 1, 99));

	std::decay_t<decltype(slabhist)>	moveslab(std::move(copyslab));

	for (int i = 0; i < 1000; i++) {
		TIME_HIST_VAL		statsarr[] {99.9, 50, 95};
		int64_t 		tcount = 0, tsum = 0;
		double 			mean_val = 0;

		ret = moveslab.get_stats(std::chrono::seconds(10), statsarr, GY_ARRAY_SIZE(statsarr), tcount, tsum, mean_val);
		if (i == 0) {
			INFOPRINTCOLOR(GY_COLOR_GREEN, "p99.9 of CPU util data items in last 10 sec have CPU <= %ld %% : Median (50 percentile) have CPU <= %ld %% : p95 have CPU <= %ld %% : Total Count %ld : Total Sum %ld : Avg  %.03lf %%\n",
				statsarr[0].data_value, statsarr[1].data_value, statsarr[2].data_value, tcount, tsum, mean_val);
		}	

		ret = moveslab.get_stats_for_period(newtime - 10, newtime + 1, statsarr, GY_ARRAY_SIZE(statsarr), tcount, tsum, mean_val);
		if (i == 0) {
			INFOPRINTCOLOR(GY_COLOR_GREEN, "p99.9 of CPU util data items for the period of last 10 sec have CPU <= %ld %% : Median (50 percentile) have CPU <= %ld %% : p95 have CPU <= %ld %% : Total Count %ld : Total Sum %ld : Avg  %.03lf %%\n",
				statsarr[0].data_value, statsarr[1].data_value, statsarr[2].data_value, tcount, tsum, mean_val);
		}	

		ret = moveslab.get_stats_for_period(tnow, tnow + 1800 + 100, statsarr, GY_ARRAY_SIZE(statsarr), tcount, tsum, mean_val);
		if (i == 0) {
			INFOPRINTCOLOR(GY_COLOR_GREEN, "p99.9 of CPU util data items for the period of half an hour earlier have CPU <= %ld %% : Median (50 percentile) have CPU <= %ld %% : p95 have CPU <= %ld %% : Total Count %ld : Total Sum %ld : Avg  %.03lf %%\n",
				statsarr[0].data_value, statsarr[1].data_value, statsarr[2].data_value, tcount, tsum, mean_val);
		}	
	}	

	return 0; 

}	

void * slab_thread(void *arg)
{
	RESP_TIME_HISTOGRAM<SCOPE_GY_MUTEX>		*phistarr;
	CPU_HISTOGRAM					*phistcpu;
	const size_t					nhist = 20 * 1024;
	
	phistarr = new RESP_TIME_HISTOGRAM<SCOPE_GY_MUTEX>[nhist]();
	phistcpu = new CPU_HISTOGRAM("CPU");
	
	test_gy_slab_resp(phistarr[0]);

	gy_nanosleep(2, 0);

	test_resp_using_cache(phistarr[1]);

	gy_nanosleep(2, 0);

	test_gy_slab_cpu(*phistcpu);
	
	gy_nanosleep(2, 0);

	delete [] phistarr;
	delete phistcpu;

	return nullptr;
}	

MAKE_PTHREAD_FUNC_WRAPPER(slab_thread);

void *debug_thread(void *arg)
{
	PROC_CPU_IO_STATS		procstats(getpid(), getpid(), true);

	while (1) {
		gy_nanosleep(1, 0);

		procstats.get_current_stats(true);
	}

	return nullptr;
}	

MAKE_PTHREAD_FUNC_WRAPPER(debug_thread);

int main(int argc, char *argv[])
{
	gdebugexecn = 10;
	
	GY_SIGNAL_HANDLER::init_singleton(argv[0]);

	int					ret;
	pthread_t				slbtid, dbgtid;
	
	gy_create_thread(&dbgtid, GET_PTHREAD_WRAPPER(debug_thread), nullptr);
	gy_create_thread(&slbtid, GET_PTHREAD_WRAPPER(slab_thread), nullptr);
	
	pthread_join(slbtid, nullptr);

/* 	pthread_cancel(dbgtid); */
/* 	pthread_join(dbgtid, nullptr); */
	
	return 0;
}	

