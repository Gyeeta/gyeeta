//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include 		<thread>

static constexpr int	MAX_OUTER = 1'000'000;	

static int64_t		firstdiff;

void bench_strncpy(const std::unique_ptr<char []> * pstrarr, char *pbuf, size_t szbuf)
{
	// First touch the addresses to prevent page faults
	for (int i = 0; i < 10; ++i) {
		strncpy(pbuf, pstrarr[i].get(), szbuf - 1);
		pbuf[szbuf - 1] = 0;
	}	
	
	auto			cnsec = gyeeta::get_nsec_clock(), ensec = 0ul;

	for (int j = 0; j < MAX_OUTER; ++j) {
		for (int i = 0; i < 10; ++i) {
			strncpy(pbuf, pstrarr[i].get(), szbuf - 1);
			pbuf[szbuf - 1] = 0;

			GY_CC_BARRIER();
		}	
	}

	ensec = gyeeta::get_nsec_clock();

	firstdiff = ensec - cnsec;

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Total Time for %d strncpy is %lu nsec (Avg %lu nsec)\n", MAX_OUTER * 10, ensec - cnsec, (ensec - cnsec)/MAX_OUTER/10);
}	

void bench_gy_strncpy(const std::unique_ptr<char []> * pstrarr, char *pbuf, size_t szbuf)
{
	// First touch the addresses to prevent page faults
	for (int i = 0; i < 10; ++i) {
		strncpy(pbuf, pstrarr[i].get(), szbuf - 1);
		pbuf[szbuf - 1] = 0;
	}	

	auto			cnsec = gyeeta::get_nsec_clock(), ensec = 0ul;

	for (int j = 0; j < MAX_OUTER; ++j) {
		for (int i = 0; i < 10; ++i) {
			GY_STRNCPY(pbuf, pstrarr[i].get(), szbuf - 1);
			pbuf[szbuf - 1] = 0;

			GY_CC_BARRIER();
		}	
	}

	ensec = gyeeta::get_nsec_clock();

	int64_t		secdiff = ensec - cnsec;

	INFOPRINTCOLOR(GY_COLOR_YELLOW, "Total Time for %d GY_STRNCPY is %ld nsec (Avg %ld nsec) %.02lf%% (%s)\n", 
		MAX_OUTER * 10, secdiff, secdiff/MAX_OUTER/10, ((secdiff - firstdiff) * 100.0)/firstdiff, secdiff <= firstdiff ? "faster" : "slower"); 
}	

void bench_strncpy_0(const std::unique_ptr<char []> * pstrarr, char *pbuf, size_t szbuf)
{
	// First touch the addresses to prevent page faults
	for (int i = 0; i < 10; ++i) {
		strncpy(pbuf, pstrarr[i].get(), szbuf - 1);
		pbuf[szbuf - 1] = 0;
	}	
	
	auto			cnsec = gyeeta::get_nsec_clock(), ensec = 0ul;

	for (int j = 0; j < MAX_OUTER; ++j) {
		for (int i = 0; i < 10; ++i) {
			GY_STRNCPY_0(pbuf, pstrarr[i].get(), szbuf - 1);
			pbuf[szbuf - 1] = 0;

			GY_CC_BARRIER();
		}	
	}

	ensec = gyeeta::get_nsec_clock();

	firstdiff = ensec - cnsec;

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Total Time for %d GY_STRNCPY_0 is %lu nsec (Avg %lu nsec)\n", MAX_OUTER * 10, ensec - cnsec, (ensec - cnsec)/MAX_OUTER/10);
}	


void test_both(size_t max_src_strlen, char *pbuf, size_t szbuf)
{
	std::unique_ptr<char []>		uniqarr[30];

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing both using source strlen %lu and max dest length of %lu\n", max_src_strlen, szbuf);

	for (size_t i = 0; i < GY_ARRAY_SIZE(uniqarr); ++i) {
		uniqarr[i] = std::make_unique<char []>(max_src_strlen);

		auto pdata = uniqarr[i].get();

		std::memset(pdata, 'a' + i, max_src_strlen - 2);
		pdata[max_src_strlen - 1] = 0; 

		GY_CC_BARRIER();
	}	

	std::thread		t1(bench_strncpy, uniqarr, pbuf, szbuf);

	t1.join();

	std::thread		t2(bench_gy_strncpy, uniqarr + 10, pbuf, szbuf);

	t2.join();

	std::thread		t3(bench_strncpy_0, uniqarr + 20, pbuf, szbuf);

	t3.join();
}

int main()
{
	char			gbuf[64], gbuf2[512], gbuf3[4096], gbuf4[10240];
	size_t			szarr[]	{10, 30, 50, 100, 200, 400, 700, 1024, 5000};

	for (auto sz : szarr) {
		test_both(sz, gbuf, sizeof(gbuf));

		IRPRINT("\n");

		test_both(sz, gbuf2, sizeof(gbuf2));

		IRPRINT("\n");

		test_both(sz, gbuf3, sizeof(gbuf3));

		IRPRINT("\n");

		test_both(sz, gbuf4, sizeof(gbuf4));

		IRPRINT("\n");
	}	

	return 0;
}	

