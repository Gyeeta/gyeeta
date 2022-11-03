//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"

#include 		"folly/stats/QuantileEstimator-defs.h"
#include 		"folly/stats/QuantileEstimator.h"

using namespace		gyeeta;
using namespace 	folly;

struct GyClock 
{
public:
	using duration 		= std::chrono::steady_clock::duration;
	using time_point 	= std::chrono::steady_clock::time_point;

	static constexpr auto 	is_steady = true;

	static time_point now() {
		return Now;
	}

	static time_point 	Now;
};

GyClock::time_point GyClock::Now = GyClock::time_point{};

int main()
{
	SlidingWindowQuantileEstimator<GyClock> estimator(std::chrono::seconds{10}, 3);

	for (size_t i = 1; i <= 100; ++i) {
		estimator.addValue(i);
	}

	GyClock::Now += std::chrono::seconds{10};
	
	{
		auto estimates = estimator.estimateQuantiles(std::array<double, 5>{{.001, .01, .5, .99, .999}});

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Quantile Estimates given below : \n");
		for (size_t i = 0; i < 5; i++) {
			IRPRINTCOLOR(GY_COLOR_GREEN, "\t\tP%f -> %f\n", estimates.quantiles[i].first * 100.0, estimates.quantiles[i].second);
		}
	}

	GyClock::Now += std::chrono::seconds{10};

	for (size_t i = 10; i <= 10000; ++i) {
		estimator.addValue(i);
	}

	GyClock::Now += std::chrono::seconds{10};
	
	{
		auto estimates = estimator.estimateQuantiles(std::array<double, 5>{{.001, .01, .5, .99, .999}});

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Quantile Estimates given below : \n");
		for (size_t i = 0; i < 5; i++) {
			IRPRINTCOLOR(GY_COLOR_GREEN, "\t\tP%f -> %f\n", estimates.quantiles[i].first * 100.0, estimates.quantiles[i].second);
		}
	}

	GyClock::Now += std::chrono::seconds{10};
	
	for (size_t i = 10; i <= 100; ++i) {
		estimator.addValue(10000 + i);
	}

	{
		auto estimates = estimator.estimateQuantiles(std::array<double, 5>{{.001, .01, .5, .99, .999}});

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Quantile Estimates given below : \n");
		for (size_t i = 0; i < 5; i++) {
			IRPRINTCOLOR(GY_COLOR_GREEN, "\t\tP%f -> %f\n", estimates.quantiles[i].first * 100.0, estimates.quantiles[i].second);
		}
	}

	GyClock::Now += std::chrono::seconds{10};
	
	for (size_t i = 10; i <= 100; ++i) {
		estimator.addValue(20000 + i);
	}

	{
		auto estimates = estimator.estimateQuantiles(std::array<double, 5>{{.001, .01, .5, .99, .999}});

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Quantile Estimates given below : \n");
		for (size_t i = 0; i < 5; i++) {
			IRPRINTCOLOR(GY_COLOR_GREEN, "\t\tP%f -> %f\n", estimates.quantiles[i].first * 100.0, estimates.quantiles[i].second);
		}
	}

	GyClock::Now += std::chrono::seconds{10};
	
	for (size_t i = 10; i <= 100; ++i) {
		estimator.addValue(30000 + i);
	}

	{
		auto estimates = estimator.estimateQuantiles(std::array<double, 5>{{.001, .01, .5, .99, .999}});

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Quantile Estimates given below : \n");
		for (size_t i = 0; i < 5; i++) {
			IRPRINTCOLOR(GY_COLOR_GREEN, "\t\tP%f -> %f\n", estimates.quantiles[i].first * 100.0, estimates.quantiles[i].second);
		}
	}


	return 0;
}

