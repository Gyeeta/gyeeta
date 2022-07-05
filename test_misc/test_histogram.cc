
#include 		"gy_common_inc.h"
#include		"gy_statistics.h"

using namespace gyeeta;

int main()
{
	using RespHistogram = gyeeta::GY_HISTOGRAM<int64_t, RESP_TIME_HASH>;
	using CPUHistogram = gyeeta::GY_HISTOGRAM<int, PERCENT_HASH>;

#if (__cplusplus >= 201700L)
	
	using Hist_9_26 = gyeeta::GY_HISTOGRAM<int8_t, FIXED_DIFF_HASH<int8_t, 9, 26, 5>>;

	if (1) {
		Hist_9_26		hist1;
		size_t			bucketid, maxb;	
		float			pcts[] = {25.0, 50, 75, 95, 99.999};
		int8_t			data_pct1, data_pct2;

		STRING_BUFFER<2048>	strbuf;
		
		const uint64_t		tcurr = get_sec_clock();

		maxb = hist1.get_hash_class().get_max_buckets();
		assert(6 == maxb);

		bucketid = hist1.add_data(0, tcurr);
		assert(bucketid == 0);

		bucketid = hist1.add_data(8, tcurr);
		assert(bucketid == 0);

		bucketid = hist1.add_data(9, tcurr);
		assert(bucketid == 1);

		bucketid = hist1.add_data(10, tcurr);
		assert(bucketid == 1);

		bucketid = hist1.add_data(13, tcurr);
		assert(bucketid == 1);

		bucketid = hist1.add_data(14, tcurr);
		assert(bucketid == 2);

		bucketid = hist1.add_data(15, tcurr);
		assert(bucketid == 2);

		bucketid = hist1.add_data(18, tcurr);
		assert(bucketid == 2);

		bucketid = hist1.add_data(19, tcurr);
		assert(bucketid == 3);

		bucketid = hist1.add_data(20, tcurr);
		assert(bucketid == 3);

		bucketid = hist1.add_data(23, tcurr);
		assert(bucketid == 3);

		bucketid = hist1.add_data(24, tcurr);
		assert(bucketid == 4);

		data_pct1 = hist1.get_percentile(75.0);
		assert(data_pct1 == 23);

		bucketid = hist1.add_data(25, tcurr);
		assert(bucketid == 4);

		bucketid = hist1.add_data(26, tcurr);
		assert(bucketid == 4);

		bucketid = hist1.add_data(27, tcurr);
		assert(bucketid == 5);

		bucketid = hist1.add_data(40, tcurr);
		assert(bucketid == 5);

		data_pct2 = hist1.get_percentile(90.0);
		assert(data_pct2 == 26);

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Histogram Stats : %s\n\n", hist1.print_stats(strbuf, pcts, GY_ARRAY_SIZE(pcts)));
	}	

	using Hist_n4 = gyeeta::GY_HISTOGRAM<int, FIXED_DIFF_HASH<int, -15, -3, 4>>;

	if (1) {
		Hist_n4			hist1;
		size_t			bucketid, maxb;	
		float			pcts[] = {25.0, 50, 75, 95, 99.999};
		int			data_pct1, data_pct2;

		STRING_BUFFER<2048>	strbuf;
		
		maxb = hist1.get_hash_class().get_max_buckets();
		assert(6 == maxb);

		bucketid = hist1.add_data(0);
		assert(bucketid == 5);

		bucketid = hist1.add_data(-16);
		assert(bucketid == 0);

		bucketid = hist1.add_data(-15);
		assert(bucketid == 1);

		bucketid = hist1.add_data(-13);
		assert(bucketid == 1);

		bucketid = hist1.add_data(-12);
		assert(bucketid == 1);

		bucketid = hist1.add_data(-11);
		assert(bucketid == 2);

		bucketid = hist1.add_data(-10);
		assert(bucketid == 2);

		bucketid = hist1.add_data(-8);
		assert(bucketid == 2);

		data_pct1 = hist1.get_percentile(75.0);
		assert(data_pct1 == -8);

		bucketid = hist1.add_data(-7);
		assert(bucketid == 3);

		bucketid = hist1.add_data(-5);
		assert(bucketid == 3);

		bucketid = hist1.add_data(-4);
		assert(bucketid == 3);

		bucketid = hist1.add_data(-3);
		assert(bucketid == 4);

		bucketid = hist1.add_data(-2);
		assert(bucketid == 5);

		data_pct2 = hist1.get_percentile(75.0);
		assert(data_pct2 == -4);

		bucketid = hist1.add_data(2);
		assert(bucketid == 5);

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Histogram Stats : %s\n\n", hist1.print_stats(strbuf, pcts, GY_ARRAY_SIZE(pcts)));
	}	

#endif

	if (1) {
		RespHistogram		resphist(20000);
		size_t			bucketid;	
		float			pcts[] = {1, 25.0, 50, 75, 95, 99, 99.99};

		STRING_BUFFER<2048>	strbuf;

		bucketid = resphist.add_data(0, 20000);
		bucketid = resphist.add_data(2, 20000);
		bucketid = resphist.add_data(2000, 20000);
		bucketid = resphist.add_data(1000'000, 30000);

		for (int i = 0; i < 1000; i++) {
			resphist.add_data(i, 30000 + i);  
		}	

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Response Histogram Stats : %s\n\n", resphist.print_stats(strbuf, pcts, GY_ARRAY_SIZE(pcts), "Response msec"));
	}
	
	IRPRINT("\n\n");

	if (1) {
		CPUHistogram		cpuhist;
		size_t			bucketid;	
		float			pcts[] = {1, 25.0, 50, 75, 95, 99, 99.9999};

		STRING_BUFFER<2048>	strbuf;

		bucketid = cpuhist.add_data(0);
		bucketid = cpuhist.add_data(2);
		bucketid = cpuhist.add_data(20);
		bucketid = cpuhist.add_data(90);
		bucketid = cpuhist.add_data(25);
		bucketid = cpuhist.add_data(35);
		bucketid = cpuhist.add_data(55);
		bucketid = cpuhist.add_data(65);

		for (int i = 0; i < 100; i++) {
			cpuhist.add_data(i + i);    
		}	

		INFOPRINTCOLOR(GY_COLOR_GREEN, "CPU Histogram Stats : %s\n\n", cpuhist.print_stats(strbuf, pcts, GY_ARRAY_SIZE(pcts), "CPU %"));
	}

	if (1) {
		CPUHistogram		cpuhist, cpuhist2;
		size_t			bucketid;	
		float			pcts[] = {25.0, 50, 75, 95, 99, 99.9};

		STRING_BUFFER<2048>	strbuf;

		for (int i = 0; i < 100; i++) {
			cpuhist.add_data(i);    
		}	

		for (int i = 10; i < 50; i++) {
			cpuhist.add_data(i);    
			cpuhist.add_data(i);    
			cpuhist.add_data(i);    
		}	

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Test for Copy assignment : Initial CPU Histogram Stats : %s\n\n", cpuhist.print_stats(strbuf, pcts, GY_ARRAY_SIZE(pcts), "CPU %"));

		strbuf.reset();

		cpuhist2.add_histogram(cpuhist);

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Test for add_histogram : After add CPU Histogram Stats : %s\n\n", cpuhist2.print_stats(strbuf, pcts, GY_ARRAY_SIZE(pcts), "CPU %"));

		strbuf.reset();

		decltype(cpuhist)	mhist = std::move(cpuhist2);

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Test for Move construction : After move CPU Histogram Stats : %s\n\n", mhist.print_stats(strbuf, pcts, GY_ARRAY_SIZE(pcts), "CPU %"));

		HIST_SERIAL		stats_arr[PERCENT_HASH::get_max_buckets()];
		size_t			total_count;
		int			max_val;
		uint64_t 		end_clock, start_clock;

		mhist.get_serialized(stats_arr, total_count, max_val, end_clock, start_clock);

		CPUHistogram		thist;

		strbuf.reset();

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Test for serialization : Before serialize CPU Histogram Stats : %s\n\n", thist.print_stats(strbuf, pcts, GY_ARRAY_SIZE(pcts), "CPU %"));
		
		strbuf.reset();

		thist.update_from_serialized(stats_arr, total_count, max_val, end_clock, start_clock);

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Test for serialization : After serialize CPU Histogram Stats : %s\n\n", thist.print_stats(strbuf, pcts, GY_ARRAY_SIZE(pcts), "CPU %"));
	}
	
	if (1) {
	
		using LogHistogramData = gyeeta::GY_HISTOGRAM_DATA<int, SEMI_LOG_HASH, 12>;

		LogHistogramData	loghist;
		size_t			bucketid;	
		float			pcts[] = {1, 25.0, 50, 75, 95, 99, 99.99};

		STRING_BUFFER<2048>	strbuf;

		bucketid = loghist.add_data(0);
		bucketid = loghist.add_data(2);
		bucketid = loghist.add_data(2000);
		bucketid = loghist.add_data(1000'000);

		for (int i = 0; i < 1000; i++) {
			loghist.add_data(i * 4);  
		}	

		loghist.add_data(50000);
		loghist.add_data(125000);

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Log Histogram Stats : %s\n\n", loghist.print_stats(strbuf, pcts, GY_ARRAY_SIZE(pcts)));

	}	

	return 0;
}	

