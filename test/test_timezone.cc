//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include 		"gy_common_inc.h"
#include 		<sys/wait.h>

using namespace gyeeta;

int main()
{
	struct timeval		tv;
	struct tm		tm, tm1, tm2;
	time_t			tcur, tcur2, tnxt;
	int64_t			nsec, nsec2;
	char			timebuf[128];
	bool			bret;
	int			tzoff, indtzoff, nytzoff;

	GY_TIMEZONE::init_singleton(); 

	gettimeofday(&tv, nullptr);

	localtime_r(&tv.tv_sec, &tm);

	GY_TIME_OFFSET		tmoff(tm, tv.tv_sec);

	INFOPRINT("Current time in ISO8601 format		: %s : Current Timezone is %s\n", 
		gy_localtime_iso8601(tv, timebuf, sizeof(timebuf)), GY_TIMEZONE::get_singleton()->get_tz_string());

	GY_TIMEZONE::get_singleton()->set_new_proc_timezone("Asia/Kolkata");

	INFOPRINT("Current India time            		: %s : Current Timezone is %s\n", 
		gy_localtime_iso8601(tv, timebuf, sizeof(timebuf)), GY_TIMEZONE::get_singleton()->get_tz_string());

	bret = gy_iso8601_to_timespec(timebuf, tcur, nsec);
	
	assert(bret == true && tcur == tv.tv_sec);

	bret = gy_iso8601_to_timespec("2018-06-01T12:34:56.123456+05:30", tcur, nsec);

	assert(bret == true);

	bret = gy_iso8601_to_timespec("2018-06-01 12:34:56.123457789 +5:30", tcur2, nsec2);

	assert(bret == true && tcur == tcur2 && 123457789 == nsec2);

	bret = gy_iso8601_to_timespec("2018-06-01T12:34:57+0530", tcur, nsec);

	assert(bret == true && tcur == tcur2 + 1);

	bret = gy_iso8601_to_timespec("2018-06-01T12:34:57Z", tcur2, nsec2);

	assert(bret == true && tcur2 == tcur + 5 * 3600 + 1800);

	bret = gy_iso8601_to_timespec("2018-06-01T12:34:57.123456", tcur, nsec);

	assert(bret == true && tcur2 == tcur + 5 * 3600 + 1800);	// As India TZ

	bret = gy_iso8601_to_timespec("2018-06-01 12:34:57.123-05:00", tcur2, nsec2);

	assert(bret == true && tcur2 == tcur + 10 * 3600 + 1800 && nsec2 == 123 * GY_NSEC_PER_MSEC);

	GY_TIMEZONE::get_singleton()->set_new_proc_timezone("America/New_York");

	INFOPRINT("Current NY time           			: %s : Current Timezone is %s\n", 
		gy_localtime_iso8601(tv, timebuf, sizeof(timebuf)), GY_TIMEZONE::get_singleton()->get_tz_string());

	bret = gy_iso8601_to_timespec(timebuf, tcur, nsec);
	
	assert(bret == true && tcur == tv.tv_sec);

	bret = gy_iso8601_to_timespec("2024-03-10 02:00:01", tcur, nsec);
	
	assert(bret == true);

	localtime_r(&tcur, &tm2);

	GY_TIME_OFFSET			nytm(tm2, tcur);

	INFOPRINT("EST to EDT Time in NY in ISO8601		: %s\n", nytm.get_iso8601_offset(0).get());

	INFOPRINT("EST to EDT Time - 10 sec in NY in ISO8601	: %s\n", nytm.get_iso8601_offset(-10).get());

	get_tm_sec_offset(tm2, -10);

	INFOPRINT("EST to EDT Time - 10 sec in NY in ISO8601	: %s\n", gy_tm_iso8601(tm2, timebuf, sizeof(timebuf)));


	GY_TIMEZONE::get_singleton()->set_new_proc_timezone("Japan");

	pid_t			cpid = fork();

	if (cpid == 0) {
		INFOPRINT("Current Japan time in child   		: %s : Current Timezone is %s\n", 
			gy_localtime_iso8601(tv, timebuf, sizeof(timebuf)), GY_TIMEZONE::get_singleton()->get_tz_string());

		bret = gy_iso8601_to_timespec(timebuf, tcur, nsec);
		
		assert(bret == true && tcur == tv.tv_sec);
		
		_exit(0);
	}
	
	waitpid(cpid, nullptr, 0);

	INFOPRINT("Current UTC time            		: %s : Current Timezone is %s\n", 
		gy_utc_time_iso8601(tv, timebuf, sizeof(timebuf)), GY_TIMEZONE::get_singleton()->get_tz_string());

	bret = gy_iso8601_to_timespec(timebuf, tcur, nsec);
	
	assert(bret == true && tcur == tv.tv_sec);

	IRPRINT("\n\n");

	// Current TZ is Japan
	tzoff = get_tz_offset_from_utc();
	INFOPRINT("Japan Timezone Offset from UTC is %d sec (%.2f hours)\n", tzoff, tzoff/3600.0f); 

	GY_TIMEZONE::get_singleton()->set_new_proc_timezone("America/New_York");

	nytzoff = tzoff = get_tz_offset_from_utc();
	INFOPRINT("NY Timezone Offset from UTC is %d sec (%.2f hours)\n", tzoff, tzoff/3600.0f); 

	GY_TIMEZONE::get_singleton()->set_new_proc_timezone("Asia/Kolkata");

	indtzoff = tzoff = get_tz_offset_from_utc();
	INFOPRINT("India Timezone Offset from UTC is %d sec (%.2f hours)\n", tzoff, tzoff/3600.0f); 
	
	IRPRINT("\n\n");

	tnxt = get_day_start(tcur);

	INFOPRINT("Current day start in India time in ISO8601	: %s\n", gy_localtime_iso8601(tnxt, timebuf, sizeof(timebuf)));

	tnxt = get_ndays_start(tcur);

	INFOPRINT("Next Day start in India time in ISO8601 	: %s\n", gy_localtime_iso8601(tnxt, timebuf, sizeof(timebuf)));

	GY_TIMEZONE::get_singleton()->set_new_proc_timezone("America/New_York");

	tnxt = get_day_start(tcur);

	INFOPRINT("Current day start in NY time in ISO8601	: %s\n", gy_localtime_iso8601(tnxt, timebuf, sizeof(timebuf)));

	tnxt = get_ndays_start(tcur);

	INFOPRINT("Next Day start in NY time in ISO8601 	: %s\n", gy_localtime_iso8601(tnxt, timebuf, sizeof(timebuf)));

	tnxt = get_ndays_start(tcur, -2);

	INFOPRINT("2 Days Prior to today in NY time in ISO8601 : %s\n", gy_localtime_iso8601(tnxt, timebuf, sizeof(timebuf)));

	IRPRINT("\n\n");

	gmtime_r(&tcur, &tm1);
	
	tm = tm1;

	nsec = 1234567;

	INFOPRINT("Current Time in UTC in ISO8601		: %s\n", gy_tm_iso8601(tm, timebuf, sizeof(timebuf), &nsec, true /* is_nsec_subsec */));

	get_tm_sec_offset(tm, -10, tcur);

	INFOPRINT("Current Time - 10 sec in UTC in ISO8601	: %s\n", gy_tm_iso8601(tm, timebuf, sizeof(timebuf), &nsec, true /* is_nsec_subsec */));

	tm = tm1;
	nsec = 1234;

	get_tm_sec_offset(tm, -30);

	INFOPRINT("Current Time - 30 sec in UTC in ISO8601	: %s\n\n", gy_tm_iso8601(tm, timebuf, sizeof(timebuf), &nsec, false /* is_nsec_subsec */));

	localtime_r(&tcur, &tm);

	INFOPRINT("Current Time in Localtime in ISO8601		: %s\n", tmoff.get_iso8601_offset(0, &nsec, true /* is_nsec_subsec */).get());

	INFOPRINT("Current Time - 10 sec in Localtime in ISO8601	: %s\n", tmoff.get_iso8601_offset(-10, timebuf, sizeof(timebuf), &nsec, true /* is_nsec_subsec */));

	nsec = 1234;

	INFOPRINT("Current Time - 30 sec in Localtime in ISO8601	: %s\n\n", tmoff.get_iso8601_offset(-30, &nsec, false /* is_nsec_subsec */).get());

	get_tm_offset(tm, 1, 1, 1, 0, tcur);

	INFOPRINT("Time Offset test in NY time in ISO8601	: %s\n", gy_tm_iso8601(tm, timebuf, sizeof(timebuf)));
	
	localtime_r(&tcur, &tm);

	get_tm_minute_offset(tm, 2, tcur);

	INFOPRINT("Time Offset test2 in NY time in ISO8601	: %s\n", gy_tm_iso8601(tm, timebuf, sizeof(timebuf)));
	
	gmtime_r(&tcur, &tm);

	get_tm_offset(tm, 1, 0, 0, 0, tcur);

	INFOPRINT("Time Offset test in UTC time in ISO8601	: %s\n", gy_tm_iso8601(tm, timebuf, sizeof(timebuf)));
	
	IRPRINT("\n\n");

	auto			tmind = get_tm_at_tzoffset(tm, indtzoff);
	auto			tmutc = get_tm_at_tzoffset(tm, 0);

	INFOPRINT("Corresponding time in India 		: %s\n", gy_tm_iso8601(tmind).get());
	INFOPRINT("Corresponding time in UTC 			: %s\n", gy_tm_iso8601(tmutc).get());

	IRPRINT("\n\n");


	{
		GY_TIMEZONE::get_singleton()->set_new_proc_timezone("Asia/Kolkata");

		tcur = gy_iso8601_to_time_t("2020-03-01 01:30:00+05:30");
		localtime_r(&tcur, &tm);

		INFOPRINT("Testing new time in India 			: %s\n", gy_tm_iso8601(tm).get());

		auto			tmny = get_tm_at_tzoffset(tm, str_get_tzoffset(" -04:00			"));
		auto			tmutc2 = get_tm_at_tzoffset(tm, 0);

		INFOPRINT("Corresponding time in TZ -04:00		: %s\n", gy_tm_iso8601(tmny).get());
		INFOPRINT("Corresponding time in UTC 			: %s\n", gy_tm_iso8601(tmutc2).get());
		
		IRPRINT("\n\n");
	}

	{
		GY_TIMEZONE::get_singleton()->set_new_proc_timezone("UTC");
		
		INFOPRINT("Current Timezone is %s\n", GY_TIMEZONE::get_singleton()->get_tz_string());
		
		tcur = gy_iso8601_to_time_t("2000-01-01 01:30:00Z");
		localtime_r(&tcur, &tm);

		INFOPRINT("Testing new time in UTC 			: %s\n", gy_tm_iso8601(tm).get());

		auto			tmny = get_tm_at_tzoffset(tm, str_get_tzoffset("-04:00"));
		auto			tmutc2 = get_tm_at_tzoffset(tm, indtzoff);

		INFOPRINT("Corresponding time in TZ -04:00		: %s\n", gy_tm_iso8601(tmny).get());
		INFOPRINT("Corresponding time in India 		: %s\n", gy_tm_iso8601(tmutc2).get());
		INFOPRINT("Corresponding time in TZ -09:30 		: %s\n", gy_tm_iso8601(get_tm_at_tzoffset(tm, str_get_tzoffset("	-0930		"))).get());

		IRPRINT("\n\n");
	}

	{
		GY_TIMEZONE::get_singleton()->set_new_proc_timezone("America/Los_Angeles");

		INFOPRINT("Current Timezone is %s\n", GY_TIMEZONE::get_singleton()->get_tz_string());

		tcur = gy_iso8601_to_time_t("2020-12-31 21:30:00-07:00");
		localtime_r(&tcur, &tm);

		INFOPRINT("Testing new time in LA 			: %s\n", gy_tm_iso8601(tm).get());

		auto			tmny = get_tm_at_tzoffset(tm, str_get_tzoffset("-0400"));
		auto			tmutc2 = get_tm_at_tzoffset(tm, 0);
		auto			tmsin = get_tm_at_tzoffset(tm, str_get_tzoffset("+1145", 5));

		INFOPRINT("Corresponding time in TZ -0400		: %s\n", gy_tm_iso8601(tmny).get());
		INFOPRINT("Corresponding time in UTC 			: %s\n", gy_tm_iso8601(tmutc2).get());
		INFOPRINT("Corresponding time in TZ +1145 		: %s\n", gy_tm_iso8601(tmsin).get());
		INFOPRINT("Corresponding time in TZ -11:45 		: %s\n", gy_tm_iso8601(get_tm_at_tzoffset(tm, str_get_tzoffset("-1145", 5))).get());
		INFOPRINT("Corresponding time in TZ -01:00 		: %s\n", gy_tm_iso8601(get_tm_at_tzoffset(tm, str_get_tzoffset("-01:00"))).get());
		INFOPRINT("Corresponding time in TZ -07:00 		: %s\n", gy_tm_iso8601(get_tm_at_tzoffset(tm, str_get_tzoffset("-07:00"))).get());

		IRPRINT("\n\n");
	}

	{
		GY_TIMEZONE::get_singleton()->set_new_proc_timezone("GMT-14");

		INFOPRINT("Current Timezone is %s\n", GY_TIMEZONE::get_singleton()->get_tz_string());

		tcur = gy_iso8601_to_time_t("2020-12-31 21:30:00-07:00");
		localtime_r(&tcur, &tm);

		INFOPRINT("Testing new time in GMT+14 		: %s\n", gy_tm_iso8601(tm).get());

		auto			tmny = get_tm_at_tzoffset(tm, str_get_tzoffset("-0400"));
		auto			tmutc2 = get_tm_at_tzoffset(tm, 0);
		auto			tmsin = get_tm_at_tzoffset(tm, str_get_tzoffset("+1145", 5));

		INFOPRINT("Corresponding time in TZ -0400		: %s\n", gy_tm_iso8601(tmny).get());
		INFOPRINT("Corresponding time in UTC 			: %s\n", gy_tm_iso8601(tmutc2).get());
		INFOPRINT("Corresponding time in TZ +1145 		: %s\n", gy_tm_iso8601(tmsin).get());
		INFOPRINT("Corresponding time in TZ -12:00 		: %s\n", gy_tm_iso8601(get_tm_at_tzoffset(tm, str_get_tzoffset("-1200", 5))).get());
		INFOPRINT("Corresponding time in TZ -01:00 		: %s\n", gy_tm_iso8601(get_tm_at_tzoffset(tm, str_get_tzoffset("-01:00"))).get());
		INFOPRINT("Corresponding time in TZ -07:00 		: %s\n", gy_tm_iso8601(get_tm_at_tzoffset(tm, str_get_tzoffset("-07:00"))).get());

		IRPRINT("\n\n");
	}


	IRPRINT("\n\n");
	return 0;
}	
