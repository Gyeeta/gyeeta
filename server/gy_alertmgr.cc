//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_alertmgr.h"
#include			"gy_shalerts.h"
#include			"gyshyama.h"
#include			"gy_stack_container.h"

#pragma 			GCC diagnostic push
#pragma 			GCC diagnostic ignored "-Wparentheses"
#include 			"boost/accumulators/accumulators.hpp"
#include 			"boost/accumulators/statistics/stats.hpp"
#include 			"boost/accumulators/statistics/rolling_sum.hpp"
#pragma 			GCC diagnostic pop

using namespace gyeeta::comm;
using namespace boost::accumulators;

namespace gyeeta {
namespace shyama {

static ALERTMGR			*galertmgr = nullptr;
static SHCONN_HANDLER		*gshconnhdlr = nullptr;
static SA_SETTINGS_C		*gsettings = nullptr;

struct AlertRollStats
{
	using 				AccSet = accumulator_set<int, stats<tag::rolling_sum>>;

	static constexpr size_t		AccWindowSize 		{1440/5};		// 1440 min/5 min

	time_t				tlastprint_		{0};

	AccSet		 		acc_alerts_		{tag::rolling_window::window_size = AccWindowSize};
	AccSet		 		acc_silenced_		{tag::rolling_window::window_size = AccWindowSize};
	AccSet		 		acc_inhib_		{tag::rolling_window::window_size = AccWindowSize};

	uint64_t			lastnalerts_		{0};
	uint64_t			lastnalerts_skipped_	{0};
	uint64_t			lastninvalid_alerts_	{0};
	uint64_t			lastnalerts_silenced_	{0};
	uint64_t			lastnalerts_inhib_	{0};

	uint32_t			day_alerts_		{0};
	uint32_t			day_silenced_		{0};
	uint32_t			day_inhib_		{0};

	AlertRollStats(time_t tinit = time(nullptr)) :
		tlastprint_(tinit)
	{}	
};	

/*
 * Parse a Date/Time. Supported formats :
 * "01/03", "12-31", "00:00"
 */
template <typename T> 
static bool get_datetime(const char *str, size_t len, T & data, const char **pendstr = nullptr, const char *sepstr = "/-:")
{
	ssize_t			slen;
	const char		*ptmp = str, *pend = str + len;
	char			f11, f12, f21, f22, sep;

	while (ptmp < pend && is_space_tab(*ptmp)) {
		ptmp++;
	}

	slen = pend - ptmp;

	if (slen < 5) {
		return false;
	}

	f11 	= ptmp[0];
	f12 	= ptmp[1];
	sep	= ptmp[2];
	f21	= ptmp[3];
	f22	= ptmp[4];

	if (f11 < '0' || f11 > '9') {
		return false;
	}

	if (f12 < '0' || f12 > '9') {
		return false;
	}

	if (f21 < '0' || f21 > '9') {
		return false;
	}

	if (f22 < '0' || f22 > '9') {
		return false;
	}

	if (nullptr == strchr(sepstr, sep)) {
		return false;
	}

	ptmp += 5;

	if (pendstr) {
		*pendstr = ptmp;
	}	

	data = { uint8_t((f11 - '0') * 10 + (f12 - '0')), uint8_t((f21 - '0') * 10 + (f22 - '0')) };

	return true;
}	

/*
 * Parse a Date range. Supported formats :
 * "01/03", "12-31 to 01-02"
 */
static std::optional<DATE_MMDD_RANGE> get_date_range(const char *str, size_t len, char (&ebuf)[256])
{
	DATE_MMDD		start, end;
	const char		*ptmp = str, *pend = str + len;
	bool			bret;

	*ebuf = 0;

	bret = get_datetime(ptmp, pend - ptmp, start, &ptmp, "/-");

	if (!bret) {
		snprintf(ebuf, sizeof(ebuf), "Invalid Date Format \'%s\' : e.g. usage : \"01/03\" or \"01-03\" in MMDD format", str); 
		return {};
	}	

	if ((start.first == 0 || start.first > 12) || (start.second == 0 || start.first > 31)) {
		snprintf(ebuf, sizeof(ebuf), "Invalid Date Format \'%s\' : Invalid dates", str); 
		return {};
	}

	while (ptmp < pend && is_space_tab(*ptmp)) {
		ptmp++;
	}

	if (ptmp >= pend) {
		return DATE_MMDD_RANGE(start, start);
	}	

	if (ptmp + 7 > pend) {
		snprintf(ebuf, sizeof(ebuf), "Invalid Date Format \'%s\' : Invalid/Missing end date", str); 
		return {};
	}	

	if (!(ptmp[0] == 't' and ptmp[1] == 'o')) {

		if (ptmp[0] == ',') {
			snprintf(ebuf, sizeof(ebuf), "Invalid Date Range Format \'%s\' : Require 2 or more items specified as separate strings within JSON as in [\"12/31\", \"01/01\"]", str); 
			return {};
		}

		snprintf(ebuf, sizeof(ebuf), "Invalid Date Range Format \'%s\' : Require range in format \"12-31 to 01-02\"", str); 
		return {};
	}	

	ptmp += 2;

	bret = get_datetime(ptmp, pend - ptmp, end, nullptr, "/-");

	if (!bret) {
		snprintf(ebuf, sizeof(ebuf), "Invalid Date Format \'%s\' : e.g. usage : \"01/03\" or \"01-03\" in MMDD format", ptmp); 
		return {};
	}	

	if ((end.first == 0 || end.first > 12) || (end.second == 0 || end.first > 31)) {
		snprintf(ebuf, sizeof(ebuf), "Invalid Date Format \'%s\' : Invalid dates", ptmp); 
		return {};
	}

	if (end.first < start.first || (end.first == start.first && end.second < start.second)) {
		snprintf(ebuf, sizeof(ebuf), "Invalid Date Range \'%s\' : End dates less than Start", str); 
		return {};
	}	

	return DATE_MMDD_RANGE(start, end);
}	


static bool is_space_tab_hypen(int c) noexcept
{
	return (c == ' ' || c == '\t' || c == '-');
}	

/*
 * Parse a Time range. Supported formats :
 * "01:00", "00:30 to 16:30", "00:30-16:30"
 */
static std::optional<TIME_HHMM_RANGE> get_time_range(const char *str, size_t len, char (&ebuf)[256])
{
	TIME_HHMM		start, end;
	const char		*ptmp = str, *pend = str + len;
	bool			bret;

	*ebuf = 0;

	bret = get_datetime(ptmp, pend - ptmp, start, &ptmp, ":");

	if (!bret) {
		snprintf(ebuf, sizeof(ebuf), "Invalid Date Format \'%s\' : e.g. usage : \"01:00\" or \"00:30 to 16:30\" in HHMM format", str); 
		return {};
	}	

	if ((start.first >= 24) || (start.first >= 60)) {
		snprintf(ebuf, sizeof(ebuf), "Invalid Time Format \'%s\' : Invalid hours/mins", str); 
		return {};
	}

	while (ptmp < pend && is_space_tab_hypen(*ptmp)) {
		ptmp++;
	}

	if (ptmp >= pend) {
		return TIME_HHMM_RANGE(start, start);
	}	

	if (*ptmp != 't' && ptmp[-1] == '-') {
		if (ptmp + 4 > pend) {
			snprintf(ebuf, sizeof(ebuf), "Invalid Time Format \'%s\' : Invalid/Missing end time", str); 
			return {};
		}
	}	
	else {
		if (ptmp + 7 > pend) {
			snprintf(ebuf, sizeof(ebuf), "Invalid Time Format \'%s\' : Invalid/Missing end time", str); 
			return {};
		}	

		if (!(ptmp[0] == 't' and ptmp[1] == 'o')) {
			if ((ptmp[0] == 'a' or ptmp[0] == 'p') and (ptmp[1] == 'm')) {
				snprintf(ebuf, sizeof(ebuf), "Invalid Time Range Format \'%s\' : Require time in 24 hour format e.g. \'00:30 to 15:00\'", str); 
				return {};
			}	

			if (ptmp[0] == ',') {
				snprintf(ebuf, sizeof(ebuf), "Invalid Time Range Format \'%s\' : Require 2 or more items specified as separate strings within JSON as in [\"12:30\", \"01:00\"]", str); 
				return {};
			}

			snprintf(ebuf, sizeof(ebuf), "Invalid Time Range Format \'%s\' : Require range in format \'00:30 to 15:00\'", str); 
			return {};
		}	

		ptmp += 2;
	}

	bret = get_datetime(ptmp, pend - ptmp, end, nullptr, ":");

	if (!bret) {
		snprintf(ebuf, sizeof(ebuf), "Invalid Time Format \'%s\' : e.g. usage : Time required in HHMM format as in 00:00", ptmp); 
		return {};
	}	

	if ((end.first >= 24) || (end.first >= 60)) {
		snprintf(ebuf, sizeof(ebuf), "Invalid Time Format \'%s\' : Invalid hours/mins", ptmp); 
		return {};
	}

	if (end.first < start.first || (end.first == start.first && end.second < start.second)) {
		snprintf(ebuf, sizeof(ebuf), "Invalid Time Range \'%s\' : End times less than Start", str); 
		return {};
	}	

	return TIME_HHMM_RANGE(start, end);
}	


static std::optional<std::bitset<7>> get_dayofweek_range(const char *str, size_t len, char (&ebuf)[256])
{
	static constexpr const char	*daysarr[] { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	ssize_t				slen;
	const char			*ptmp = str, *pend = str + len;
	uint32_t			i, j;
	std::bitset<7>			rset;

	*ebuf = 0;

	while (ptmp < pend && is_space_tab(*ptmp)) {
		ptmp++;
	}

	slen = pend - ptmp;

	if (slen < 3) {
		snprintf(ebuf, sizeof(ebuf), "Invalid dayofweek format \'%s\' : e.g. usage : \"Thu\" or \"Thu to Sat\"", str); 
		return {};
	}
	
	for (i = 0; i < GY_ARRAY_SIZE(daysarr); ++i) {
		if (0 == strncasecmp(ptmp, daysarr[i], 3)) {
			break;
		}	
	}	

	if (i == GY_ARRAY_SIZE(daysarr)) {
		snprintf(ebuf, sizeof(ebuf), "Invalid dayofweek format \'%s\' : e.g. usage : \"Thu\" or \"Thu to Sat\"", str); 
		return {};
	}

	rset.set(i);

	ptmp += 3;

	while (ptmp < pend && !is_space_tab_hypen(*ptmp)) {
		ptmp++;
	}	

	while (ptmp < pend && is_space_tab_hypen(*ptmp)) {
		ptmp++;
	}

	if (ptmp == pend) {
		return rset;
	}	

	if (*ptmp != 't' && ptmp[-1] == '-') {
		if (ptmp + 2 > pend) {
			snprintf(ebuf, sizeof(ebuf), "Invalid dayofweek Format \'%s\' : Invalid/Missing end day", str); 
			return {};
		}	
	}
	else {
		if (ptmp + 6 > pend) {
			snprintf(ebuf, sizeof(ebuf), "Invalid dayofweek Format \'%s\' : Invalid/Missing end day", str); 
			return {};
		}	

		if (!(*ptmp == 't' and ptmp[1] == 'o')) {

			if (ptmp[0] == ',') {
				snprintf(ebuf, sizeof(ebuf), "Invalid dayofweek format \'%s\' : Require 2 or more items specified as separate strings within JSON as in [\"Mon\", \"Thu\"]", 
						str); 
				return {};
			}

			snprintf(ebuf, sizeof(ebuf), "Invalid dayofweek Range Format \'%s\' : Require range in format \"Mon to Thu\"", str); 
			return {};
		}	

		ptmp += 2;
	}

	while (ptmp < pend && is_space_tab(*ptmp)) {
		ptmp++;
	}

	slen = pend - ptmp;

	if (slen < 3) {
		snprintf(ebuf, sizeof(ebuf), "Invalid dayofweek range format : Missing end day : \'%s\' : e.g. usage : \"Thu to Sat\"", str); 
		return {};
	}

	for (j = 0; j < GY_ARRAY_SIZE(daysarr); ++j) {
		if (0 == strncasecmp(ptmp, daysarr[j], 3)) {
			break;
		}	
	}	

	if (j == GY_ARRAY_SIZE(daysarr)) {
		snprintf(ebuf, sizeof(ebuf), "Invalid dayofweek end range format \'%s\' : e.g. usage : \"Thu\" or \"Thu to Sat\"", str); 
		return {};
	}
	
	if (j < i) {
		snprintf(ebuf, sizeof(ebuf), "Invalid dayofweek end range : End day less than Start day : \'%s\' : e.g. usage : \"Thu\" or \"Thu to Sat\"", str); 
		return {};
	}	

	for (; i <= j; ++i) {
		rset.set(i);
	}
	
	return rset;
}	

static std::optional<std::bitset<12>> get_month_range(const char *str, size_t len, char (&ebuf)[256])
{
	static constexpr const char	*montharr[] { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	ssize_t				slen;
	const char			*ptmp = str, *pend = str + len;
	uint32_t			i, j;
	std::bitset<12>			rset;

	*ebuf = 0;

	while (ptmp < pend && is_space_tab(*ptmp)) {
		ptmp++;
	}

	slen = pend - ptmp;

	if (slen < 3) {
		snprintf(ebuf, sizeof(ebuf), "Invalid months format \'%s\' : e.g. usage : \"Jan\" or \"Jan to Mar\"", str); 
		return {};
	}
	
	for (i = 0; i < GY_ARRAY_SIZE(montharr); ++i) {
		if (0 == strncasecmp(ptmp, montharr[i], 3)) {
			break;
		}	
	}	

	if (i == GY_ARRAY_SIZE(montharr)) {
		snprintf(ebuf, sizeof(ebuf), "Invalid months format \'%s\' : e.g. usage : \"Jan\" or \"Jan to Mar\"", str); 
		return {};
	}

	rset.set(i);

	ptmp += 3;

	while (ptmp < pend && !is_space_tab_hypen(*ptmp)) {
		ptmp++;
	}	

	while (ptmp < pend && is_space_tab_hypen(*ptmp)) {
		ptmp++;
	}

	if (ptmp == pend) {
		return rset;
	}	

	if (*ptmp != 't' && ptmp[-1] == '-') {
		if (ptmp + 2 > pend) {
			snprintf(ebuf, sizeof(ebuf), "Invalid months Format \'%s\' : Invalid/Missing end month", str); 
			return {};
		}	
	}
	else {
		if (ptmp + 6 > pend) {
			snprintf(ebuf, sizeof(ebuf), "Invalid months Format \'%s\' : Invalid/Missing end month", str); 
			return {};
		}	

		if (!(*ptmp == 't' and ptmp[1] == 'o')) {

			if (ptmp[0] == ',') {
				snprintf(ebuf, sizeof(ebuf), "Invalid months format \'%s\' : Require 2 or more items specified as separate strings within JSON as in [\"Mar\", \"Jun\"]", 
						str); 
				return {};
			}

			snprintf(ebuf, sizeof(ebuf), "Invalid months Range Format \'%s\' : Require range in format \"Jan to Mar\"", str); 
			return {};
		}	

		ptmp += 2;
	}

	while (ptmp < pend && is_space_tab(*ptmp)) {
		ptmp++;
	}

	slen = pend - ptmp;

	if (slen < 3) {
		snprintf(ebuf, sizeof(ebuf), "Invalid months range format : Missing end month : \'%s\' : e.g. usage : \"Jan to Mar\"", str); 
		return {};
	}

	for (j = 0; j < GY_ARRAY_SIZE(montharr); ++j) {
		if (0 == strncasecmp(ptmp, montharr[j], 3)) {
			break;
		}	
	}	

	if (j == GY_ARRAY_SIZE(montharr)) {
		snprintf(ebuf, sizeof(ebuf), "Invalid months end range format \'%s\' : e.g. usage : \"Jan\" or \"Jan to Mar\"", str); 
		return {};
	}
	
	if (j < i) {
		snprintf(ebuf, sizeof(ebuf), "Invalid months end range : End month less than Start month : \'%s\' : e.g. usage : \"Jan\" or \"Jan to Mar\"", str); 
		return {};
	}	

	for (; i <= j; ++i) {
		rset.set(i);
	}
	
	return rset;
}	

static std::optional<std::bitset<31>> get_dayofmonth_range(const char *str, size_t len, char (&ebuf)[256])
{
	ssize_t			slen;
	const char		*ptmp = str, *pend = str + len;
	char			*ptmp2 = nullptr;
	uint32_t		start, end;
	bool			bret;
	std::bitset<31>		rset;

	*ebuf = 0;

	while (ptmp < pend && is_space_tab(*ptmp)) {
		ptmp++;
	}

	bret = string_to_number(ptmp, start, &ptmp2, 10);

	if (!bret) {
		snprintf(ebuf, sizeof(ebuf), "Invalid dayofmonth format \'%s\' : e.g. usage : \"1\" or \"10 to 20\"", str); 
		return {};
	}	

	if (start == 0 or start > 31) {
		snprintf(ebuf, sizeof(ebuf), "Invalid dayofmonth day specified \'%s\' : e.g. usage : \"1\" or \"10 to 20\"", str); 
		return {};
	}

	if (!ptmp2 || *ptmp2 == 0) {
		rset.set(start - 1);
		return rset;
	}	
	
	ptmp = ptmp2;

	while (ptmp < pend && is_space_tab_hypen(*ptmp)) {
		ptmp++;
	}

	if (ptmp == pend) {
		rset.set(start - 1);
		return rset;
	}	

	if (*ptmp != 't' && ptmp[-1] == '-') {
		if (ptmp + 1 > pend) {
			snprintf(ebuf, sizeof(ebuf), "Invalid dayofmonth Format \'%s\' : Invalid/Missing end day", str); 
			return {};
		}	
	}
	else {
		if (ptmp + 4 > pend) {
			snprintf(ebuf, sizeof(ebuf), "Invalid dayofmonth Format \'%s\' : Invalid/Missing end day", str); 
			return {};
		}	

		if (!(*ptmp == 't' and ptmp[1] == 'o')) {

			if (ptmp[0] == ',') {
				snprintf(ebuf, sizeof(ebuf), "Invalid dayofmonth format \'%s\' : Require 2 or more items specified as separate strings within JSON as in [\"1\", \"2\"]", 
						str); 
				return {};
			}

			snprintf(ebuf, sizeof(ebuf), "Invalid dayofmonth Range Format \'%s\' : Require range in format \"10 to 15\"", str); 
			return {};
		}	

		ptmp += 2;
	}

	while (ptmp < pend && is_space_tab(*ptmp)) {
		ptmp++;
	}

	if (ptmp == pend) {
		snprintf(ebuf, sizeof(ebuf), "Invalid dayofmonth Range format \'%s\' : e.g. usage : \"10 to 20\"", str); 
		return {};
	}

	bret = string_to_number(ptmp, end, nullptr, 10);

	if (!bret) {
		snprintf(ebuf, sizeof(ebuf), "Invalid dayofmonth end day format \'%s\' : e.g. usage : \"1\" or \"10 to 20\"", str); 
		return {};
	}	

	if (end == 0 or end > 31) {
		snprintf(ebuf, sizeof(ebuf), "Invalid dayofmonth end day specified \'%s\' : e.g. usage : \"1\" or \"10 to 20\"", str); 
		return {};
	}

	if (end < start) {
		snprintf(ebuf, sizeof(ebuf), "Invalid dayofmonth range : End day less than Start day : \'%s\' : e.g. usage : \"1 to 10\"", str); 
		return {};
	}	

	for (; start <= end; ++start) {
		rset.set(start - 1);
	}
	
	return rset;
}	

bool MUTE_ONE::in_range(const struct tm & tm1, time_t tcurr) const
{
	struct tm		tm = get_tm_at_tzoffset(tm1, tzoffset_);
	size_t 			i;

	if ((false == dayofmonth_.test(tm.tm_mday - 1)) || (false == months_.test(tm.tm_mon)) || (false == dayofweek_.test(tm.tm_wday))) {
		return false;
	}	

	if (is_mmdd()) {
		for (i = 0; i < daterange_.size(); ++i) {
			if (true == daterange_[i].in_range(tm)) {
				break;
			}	
		}	

		if (i == daterange_.size()) {
			return false;
		}	
	}	

	if (is_timerange()) {
		for (i = 0; i < timerange_.size(); ++i) {
			if (true == timerange_[i].in_range(tm)) {
				break;
			}	
		}	

		if (i == timerange_.size()) {
			return false;
		}	
	}	
	
	return true;
}

std::pair<bool, bool> MUTE_ONE::in_same_range(const struct tm & tm1, time_t tcurr1, const struct tm & tm2, time_t tcurr2) const
{
	struct tm		tm = get_tm_at_tzoffset(tm1, tzoffset_);
	uint32_t		i;
	bool			is_same = true;

	if ((false == dayofmonth_.test(tm.tm_mday - 1)) || (false == months_.test(tm.tm_mon)) || (false == dayofweek_.test(tm.tm_wday))) {
		return {false, false};
	}	

	struct tm		etm = get_tm_at_tzoffset(tm2, tzoffset_);

	if ((false == dayofmonth_.test(etm.tm_mday - 1)) || (false == months_.test(etm.tm_mon)) || (false == dayofweek_.test(etm.tm_wday))) {
		is_same = false;
	}	

	if (is_mmdd()) {
		for (i = 0; i < daterange_.size(); ++i) {
			if (true == daterange_[i].in_range(tm)) {
				if (is_same && false == daterange_[i].in_range(etm)) {
					is_same = false;
				}	
				break;
			}	
		}	

		if (i == daterange_.size()) {
			return {false, false};
		}	
	}	

	if (is_timerange()) {
		for (i = 0; i < timerange_.size(); ++i) {
			if (true == timerange_[i].in_range(tm)) {
				if (is_same && false == timerange_[i].in_range(etm)) {
					is_same = false;
				}	
				break;
			}	
		}	

		if (i == timerange_.size()) {
			return {false, false};
		}	
	}	

	return {true, is_same};
}	

MUTE_ONE::MUTE_ONE(const GEN_JSON_VALUE & jval)
{
	char			ebuf[256];
	int			is_dom = 0, is_month = 0, is_dow = 0;

	if (false == jval.IsObject()) {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON : Not of an Object type");
	}	

	*ebuf = 0;

	if (auto it = jval.FindMember("dates_mmdd"); (it != jval.MemberEnd())) {
		const auto		& darr = it->value;

		if (false == darr.IsArray()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON : dates_mmdd field not of Array Type");
		}	

		daterange_.reserve(darr.Size());

		for (int i = 0; i < (int)darr.Size(); ++i) {
			if (false == darr[i].IsString()) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON : dates_mmdd Array Element field not of String Type");
			}

			*ebuf		= 0;

			auto		drange = get_date_range(darr[i].GetString(), darr[i].GetStringLength(), ebuf);

			if (!drange) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON field dates_mmdd : %s", ebuf);
			}

			daterange_.push_back(*drange);
		}	
	}	
	
	if (auto it = jval.FindMember("timerange"); (it != jval.MemberEnd())) {
		const auto		& darr = it->value;

		if (false == darr.IsArray()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON : timerange field not of Array Type");
		}	

		timerange_.reserve(darr.Size());

		for (int i = 0; i < (int)darr.Size(); ++i) {
			if (false == darr[i].IsString()) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON : timerange Array Element field not of String Type");
			}

			*ebuf		= 0;

			auto		drange = get_time_range(darr[i].GetString(), darr[i].GetStringLength(), ebuf);

			if (!drange) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON field timerange : %s", ebuf);
			}

			timerange_.push_back(*drange);
		}	
	}	

	if (auto it = jval.FindMember("months"); (it != jval.MemberEnd())) {
		const auto		& darr = it->value;

		if (false == darr.IsArray()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON : months field not of Array Type");
		}	

		is_month = 1;

		months_.reset();

		for (int i = 0; i < (int)darr.Size(); ++i) {
			if (false == darr[i].IsString()) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON : months Array Element field not of String Type");
			}

			*ebuf		= 0;

			auto		drange = get_month_range(darr[i].GetString(), darr[i].GetStringLength(), ebuf);

			if (!drange) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON field months : %s", ebuf);
			}

			months_ |= *drange;
		}	
	}	

	if (auto it = jval.FindMember("dayofweek"); (it != jval.MemberEnd())) {
		const auto		& darr = it->value;

		if (false == darr.IsArray()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON : dayofweek field not of Array Type");
		}	

		is_dow = 1;

		dayofweek_.reset();

		for (int i = 0; i < (int)darr.Size(); ++i) {
			if (false == darr[i].IsString()) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON : dayofweek Array Element field not of String Type");
			}

			*ebuf		= 0;

			auto		drange = get_dayofweek_range(darr[i].GetString(), darr[i].GetStringLength(), ebuf);

			if (!drange) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON field dayofweek : %s", ebuf);
			}

			dayofweek_ |= *drange;
		}	
	}	

	if (auto it = jval.FindMember("dayofmonth"); (it != jval.MemberEnd())) {
		const auto		& darr = it->value;

		if (false == darr.IsArray()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON : dayofmonth field not of Array Type");
		}	

		is_dom = 1;

		dayofmonth_.reset();

		for (int i = 0; i < (int)darr.Size(); ++i) {

			if (darr[i].IsUint()) {
				uint32_t		day = darr[i].GetUint();

				if (day == 0 || day > 31) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON : dayofmonth field invalid value %u (must be between 1-31)", day);
				}	

				dayofmonth_.set(day - 1);

				continue;
			}	
			else if (false == darr[i].IsString()) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON : dayofmonth Array Element field not of Number or String Type");
			}

			*ebuf		= 0;

			auto		drange = get_dayofmonth_range(darr[i].GetString(), darr[i].GetStringLength(), ebuf);

			if (!drange) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON field dayofmonth : %s", ebuf);
			}

			dayofmonth_ |= *drange;
		}	
	}	

	if (auto it = jval.FindMember("tz"); (it != jval.MemberEnd())) {
		const auto		& tz = it->value;

		if (false == tz.IsString()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON : tz field not of String Type");
		}	

		tzoffset_ = str_get_tzoffset(tz.GetString(), tz.GetStringLength());
	}

	if ((!is_mmdd()) && (!is_timerange()) && (is_month + is_dom + is_dow == 0)) {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid JSON : No Mute criterion set");
	}	
}	


bool MUTE_TIMES::in_range(const struct tm & tm, time_t tcurr) noexcept
{
	try {
		for (const auto & mone : mutevec_) {
			if (true == mone.in_range(tm, tcurr)) {

				if (tmuteend_ < tcurr - 1) {
					tmutestart_ 	= tcurr;
				}

				tmuteend_ 	= to_next_min(tcurr + 1) - 1;

				return true;
			}	
		}	

		return false;
	}
	GY_CATCH_EXPRESSION(
		DEBUGEXECN(1,
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking Alert Mute Time Hit : %s\n", GY_GET_EXCEPT_STRING);
		);
		return false;
	);	
}

bool MUTE_TIMES::in_range(const struct tm & tm1, time_t tcurr1, const struct tm & tm2, time_t tcurr2) noexcept
{
	try {
		for (const auto & mone : mutevec_) {
			auto 		[hit1, hit2] = mone.in_same_range(tm1, tcurr1, tm2, tcurr2);

			if (hit1) {
				if (tmuteend_ < tcurr1 - 1) {
					tmutestart_ 	= tcurr1;
				}

				tmuteend_	= (hit2 ? tcurr2 : to_next_min(tcurr1 + 1) - 1);

				return true;
			}
		}	

		return false;
	}
	GY_CATCH_EXPRESSION(
		DEBUGEXECN(1,
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking Alert Mute Time Hit Range : %s\n", GY_GET_EXCEPT_STRING);
		);
		return false;
	);	
}	

MUTE_TIMES::MUTE_TIMES(const GEN_JSON_VALUE & jval)
{
	if (false == jval.IsArray()) {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Mute Time JSON : Not of an Array type");
	}	

	if (0 == jval.Size()) {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Mute Time JSON : Empty Array seen");
	}

	mutevec_.reserve(jval.Size());

	for (int i = 0; i < (int)jval.Size(); ++i) {
		mutevec_.emplace_back(jval[i]);
	}	
}


ALERT_SILENCE::ALERT_SILENCE(const GEN_JSON_VALUE & jval, uint32_t silid, time_t tcreate, bool is_disabled)
	: tcreate_(tcreate), silid_(silid), is_disabled_(is_disabled)
{
	if (false == jval.IsObject()) {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Silence JSON : Not of an Object type");
	}	

	if (auto it = jval.FindMember("name"); (it != jval.MemberEnd())) {
		if (false == it->value.IsString()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Silence JSON : name field not of String Type");
		}	

		const char		*pname = it->value.GetString(), *ptmp;

		validate_json_name(pname, it->value.GetStringLength(), MAX_ALERT_NAME_LEN, "Silence Definition");

		name_.assign(it->value.GetString(), it->value.GetStringLength());

		if (silid_ == 0) {
			silid_ = get_adef_id(name_.data(), name_.length());
		}	
	}	
	else {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Silence JSON : Required field \'name\' missing");
	}	
	
	
	if (auto it = jval.FindMember("endsat"); ((it != jval.MemberEnd()) && (it->value.IsString()))) {
		tend_sec_ = gy_iso8601_to_time_t(it->value.GetString());

		if (tend_sec_ == 0) {
			tend_sec_ = LONG_MAX - 1;
		}	
		else if (tend_sec_ <= time(nullptr) + 5) {
			is_disabled_ = true;
		}	
	}
	else {
		tend_sec_ = LONG_MAX - 1;
	}	
	
	if (auto it = jval.FindMember("mutetimes"); (it != jval.MemberEnd())) {
		if (false == it->value.IsArray()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Silence Definition : mutetimes field not of Array Type");
		}	
	
		mutetimes_ = MUTE_TIMES(it->value);
	}
	else {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Silence Definition : Required field \'mutetimes\' missing");
	}	

	if (auto it = jval.FindMember("match"); (it != jval.MemberEnd())) {
		if (false == it->value.IsString()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Silence Definition : match field not of String Type");
		}	

		match_ = CRITERIA_SET(it->value.GetString(), it->value.GetStringLength(), SUBSYS_ALERTS, nullptr, true /* is_multihost */, true /* allocregex */);
	}
}

ALERT_INHIBIT::ALERT_INHIBIT(const GEN_JSON_VALUE & jval, uint32_t inhid, time_t tcreate, bool is_disabled)
	: tcreate_(tcreate), inhid_(inhid), is_disabled_(is_disabled)
{
	if (false == jval.IsObject()) {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Inhibit JSON : Not of an Object type");
	}	

	if (auto it = jval.FindMember("name"); (it != jval.MemberEnd())) {
		if (false == it->value.IsString()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Inhibit JSON : name field not of String Type");
		}	

		const char		*pname = it->value.GetString(), *ptmp;

		validate_json_name(pname, it->value.GetStringLength(), MAX_ALERT_NAME_LEN, "Inhibit Definition");

		name_.assign(it->value.GetString(), it->value.GetStringLength());

		if (inhid_ == 0) {
			inhid_ = get_adef_id(name_.data(), name_.length());
		}	
	}	
	else {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Inhibit JSON : Required field \'name\' missing");
	}	
	
	if (auto it = jval.FindMember("src_match"); (it != jval.MemberEnd())) {
		if (false == it->value.IsString()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Inhibit JSON : src_match field not of String Type");
		}	

		src_match_ = CRITERIA_SET(it->value.GetString(), it->value.GetStringLength(), SUBSYS_ALERTS, nullptr, true /* is_multihost */, true /* allocregex */);
	}
	else {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Inhibit JSON : Required field \'src_match\' missing");
	}	

	if (auto it = jval.FindMember("target_match"); (it != jval.MemberEnd())) {
		if (false == it->value.IsString()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Inhibit JSON : target_match field not of String Type");
		}	

		target_match_ = CRITERIA_SET(it->value.GetString(), it->value.GetStringLength(), SUBSYS_ALERTS, nullptr, true /* is_multihost */, true /* allocregex */);
	}
	else {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Inhibit JSON : Required field \'target_match\' missing");
	}	

	if (auto it = jval.FindMember("equal_cols"); (it != jval.MemberEnd())) {
		if (false == it->value.IsArray()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Inhibit JSON : equal_cols field not of JSON Array Type");
		}	

		equal_cols_.reserve(it->value.Size());

		for (uint32_t i = 0; i < it->value.Size(); ++i) {
			const auto		& val = it->value[i];
			const JSON_DB_MAPPING 	*pcol;

			if (false == val.IsString()) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Inhibit JSON : equal_cols Array element not of String Type");
			}	
			
			pcol = get_jsoncrc_mapping(val.GetString(), val.GetStringLength(), json_db_alerts_arr, GY_ARRAY_SIZE(json_db_alerts_arr));
			if (!pcol) {
				pcol = get_jsoncrc_mapping(val.GetString(), val.GetStringLength(), json_db_host_arr, GY_ARRAY_SIZE(json_db_host_arr));
			}	

			if (!pcol) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Inhibit JSON : equal_cols field \'%s\' not of either Alert subsystem or Host subsystem. Other subsystems not allowed",
							val.GetString());
			}	

			equal_cols_.push_back(pcol);
		}	
	}
}



ALERT_ACTION::ALERT_ACTION(const GEN_JSON_VALUE & jval, uint32_t actionid, time_t tcreate)
	: tcreate_(tcreate), actionid_(actionid)
{
	if (false == jval.IsObject()) {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Alert Action JSON : Not of an Object type");
	}	

	if (auto it = jval.FindMember("name"); (it != jval.MemberEnd())) {
		if (false == it->value.IsString()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Alert Action JSON : name field not of String Type");
		}	

		const char		*pname = it->value.GetString(), *ptmp;
		size_t			szname = it->value.GetStringLength();

		validate_json_name(pname, szname, MAX_ALERT_NAME_LEN, "Alert Action");

		if (memchr(pname, ',', szname)) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Alert Action JSON : Field \'name\' of value \'%s\' contains character \',\' which is not allowed", pname);
		}	

		name_.assign(it->value.GetString(), it->value.GetStringLength());

		if (actionid_ == 0) {
			actionid_ = get_adef_id(name_.data(), name_.length());
		}	
	}	
	else {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Alert Action JSON : Required field \'name\' missing");
	}	
	
	if (auto it = jval.FindMember("acttype"); (it != jval.MemberEnd())) {
		if (false == it->value.IsString()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Alert Action JSON : acttype field not of String Type");
		}	
	
		acttype_ = string_to_action(it->value.GetString(), true /* throw_on_err */);
	}
	else {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Alert Action JSON : Required field \'acttype\' missing");
	}	

	if (auto it = jval.FindMember("config"); (it != jval.MemberEnd())) {
		set_new_config(it->value, tcreate);
	}
	else {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Alert Action JSON : Required field \'config\' missing");
	}	

	if (auto it = jval.FindMember("send_resolved"); (it != jval.MemberEnd())) {
		if (false == it->value.IsBool()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Alert Action JSON : send_resolved field not of Boolean Type");
		}	

		send_resolved_ = it->value.GetBool();
	}
	else if (acttype_ == ACTION_PAGERDUTY || acttype_ == ACTION_WEBHOOK) {
		// Default is send_resolved_ true
		send_resolved_ = true;
	}	
}

void ALERT_ACTION::set_new_config(const GEN_JSON_VALUE & jval, time_t tcreate)
{
	if (false == jval.IsObject()) {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Alert Action JSON : config field not of Object Type");
	}	

	STACK_JSON_WRITER<4096, 2048>		writer;

	switch (acttype_) {
	
	case ACTION_NULL		:	verify_null_config(jval, writer, false /* is_override */, tcreate); break; 

	case ACTION_EMAIL		:	verify_email_config(jval, writer, false /* is_override */, tcreate); break; 

	case ACTION_SLACK		:	verify_slack_config(jval, writer, false /* is_override */, tcreate); break; 

	case ACTION_PAGERDUTY		:	verify_pagerduty_config(jval, writer, false /* is_override */, tcreate); break; 

	case ACTION_WEBHOOK		:	verify_webhook_config(jval, writer, false /* is_override */, tcreate); break; 

	default				:	break;

	}	

	config_.assign(writer.get_string(), writer.get_size());

	configid_ = fnv1_hash(config_.data(), config_.size());
}

void ALERT_ACTION::verify_null_config(const GEN_JSON_VALUE & jval, STACK_JSON_WRITER<4096, 2048> & writer, bool is_override, time_t tcreate)
{
	writer.StartObject();
	writer.EndObject();
}	

void ALERT_ACTION::verify_email_config(const GEN_JSON_VALUE & jval, STACK_JSON_WRITER<4096, 2048> & writer, bool is_override, time_t tcreate)
{
	/*
	 * List of Email options :
	 *
	 * host 			: e.g. smtp.gmail.com (mandatory)
	 * port 			: e.g. 587 for SMTP over TLS, or 465 for secure connections or 25 for older non secure SMTP servers (mandatory)
	 * secure			: Default false. Specify as true if TLS is to be used from the start such as for port 465 but non standard ports are used instead of 465
	 * tls_servername 		: is optional hostname for TLS validation if host was set to an IP address
	 * tls_reject_unauthorized 	: Default true : If set to false will skip validation of invalid or self-signed TLS certificates (optional)
	 *
	 * user				: Mandatory (Sender's email id)
	 *
	 * auth_type 			: 4 valid types login, cram_md5, oauth2 and none : Mandatory : If 'none' is specified no authentication will be done.
	 * password			: Mandatory if auth_type is login or cram_md5
	 * 
	 * OAuth2 Options follow. Currently we only support Client Credentials grant type and also Google style Authorization Params where the Client ID, Secret are sent
	 * in the Body rather than in the HTTP Authorization Header :
	 * clientid			: Mandatory : registered client id of the application
	 * client_secret		: Mandatory : registered client secret of the application
	 * access_url			: Mandatory : Endpoint for token generation (e.g. https://accounts.google.com/o/oauth2/token)
	 * refresh_token		: Optional : If provided then Gyeeta will use it to generate a new access token if existing one expires or fails
	 * access_token			: Mandatory only if refresh_token is absent : Indicates an existing OAuth2 Access Token
	 * expires_in			: Optional : Indicates Time in sec from current time when the access_token will expire (expires at current + this value in sec)
	 * expires_at			: Optional : Indicates Time in msec from 1970 when the access_token will expire (expires at this value)
	 * 
	 * use_pool			: Optional : Default is true (5 connections) : Specify as false if new connection needed for every email. 
	 *
	 * proxy_url			: Optional : HTTP / HTTPS and SOCKS5 / SOCKS4 Proxies allowed : e.g. 'http://proxy-host:1234' or 'socks5://socks-host:1234'
	 *
	 * Per Message Options valid for override :
	 *
	 * from				: Mandatory only for auth_type none : If not specified, set same as user. Formatted Name is allowed as 'Gyeeta Mail <gyeeta@myorg.local>'
	 * to				: Comma separated Receipient List : One of to, cc, bcc is mandatory e.g. 'Foo Mail <foobar@example.com>, foo2@example.com'
	 * cc				: Comma separated Receipient List : One of to, cc, bcc is mandatory e.g. 'Foo Mail <foobar@example.com>, foo2@example.com'
	 * bcc				: Comma separated Receipient List : One of to, cc, bcc is mandatory e.g. 'Foo Mail <foobar@example.com>, foo2@example.com'
	 * subject_prefix		: Optional : Email Subject will be ${subject_prefix} : Aert <State> for <Alername> : Default is 'Gyeeta Alert'
	 * headers			: Optional : Custom Headers to be sent : Needs to be an Object as in "headers" : { "x-processed" : true, "x-mykeys" : [ "val1", "val2" ] }
	 * send_text			: Optional : Default false : If true, Email will be sent in text format only and no HTML will be used.
	 */
	 
	 static constexpr const char	*nonoverrides[] 
	 		{ 	
				"host", "port", "secure", "tls_servername", "require_tls", "tls_reject_unauthorized",
				"auth_type", "user", "password", 
				"clientid", "client_secret", "access_url", "refresh_token", "access_token", "expires_in", "expires_at",
				"use_pool", "proxy_url" 
	 		};

	const char			*puser = nullptr;
	JSON_MEM_CONST_ITER		it;
	
	if (is_override) {
		for (const char * pkey : nonoverrides) {
			if (auto it = jval.FindMember(pkey); it != jval.MemberEnd()) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Action Override : Cannot override connection related field \'%s\' : "
					"Only message specific fields such as \'to\', \'subject_prefix\' can be overridden", pkey);
			}	
		}

		writer.StartObject();
		
		goto override1;
	}	
	else {

		writer.StartObject();
		
		writer.KeyConst("connection");
		writer.StartObject();

		it = jval.FindMember("host");

		if (it == jval.MemberEnd()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Missing mandatory field \'host\' : Example usage : smtp.gmail.com");
		}	
		else if (false == it->value.IsString() || !it->value.GetStringLength()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Field \'host\' not a valid String Type : Example usage : smtp.gmail.com");
		}	

		writer.KeyConst("host");
		writer.String(it->value.GetString(), it->value.GetStringLength());

		it = jval.FindMember("port");

		if (it == jval.MemberEnd()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Missing mandatory field \'host\' : Example usage : smtp.gmail.com");
		}	
		else if (false == it->value.IsUint()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Field \'port\' not of Number Type");
		}	

		uint32_t		port = it->value.GetUint();
		
		if (port == 0 || port > 65535) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Field \'port\' value %u is invalid : Please use a proper port such as 587 or 465", port);
		}	

		writer.KeyConst("port");
		writer.Int(port);
		
		it = jval.FindMember("secure");

		if (it != jval.MemberEnd() && it->value.IsBool()) {
			writer.KeyConst("secure");
			writer.Bool(it->value.GetBool());
		}
		else if (port == 465) {
			writer.KeyConst("secure");
			writer.Bool(true);
		}	

		writer.KeyConst("tls");
		
		writer.StartObject();
		
		bool			rejectunauth = false;

		it = jval.FindMember("tls_servername");

		if (it != jval.MemberEnd() && it->value.IsString()) {
			writer.KeyConst("servername");
			writer.String(it->value.GetString(), it->value.GetStringLength());
		}	

		it = jval.FindMember("tls_reject_unauthorized");

		if (it != jval.MemberEnd() && it->value.IsBool()) {
			writer.KeyConst("rejectUnauthorized");
			writer.Bool(it->value.GetBool());
		}	

		writer.EndObject();

		it = jval.FindMember("auth_type");

		if (it == jval.MemberEnd()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Missing mandatory field \'auth_type\' : "
								"Specify auth_type as any of \'login\', \'oauth2\', \'cram_md5\' or \'none\' for no authentication");
		}	
		else if (false == it->value.IsString()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : field \'auth_type\' not a valid String type : "
								"Specify auth_type as any of \'login\', \'oauth2\', \'cram_md5\' or \'none\' for no authentication");
		}	
		
		const char			*pauthtype = nullptr;
		bool				is_login = false, is_cram = false, is_oauth2 = false, is_none = false;

		pauthtype = it->value.GetString();

		if (0 == strcasecmp(pauthtype, "login")) {
			is_login = true;
		}	
		else if (0 == strcasecmp(pauthtype, "cram_md5")) {
			is_cram = true;
		}	
		else if (0 == strcasecmp(pauthtype, "oauth2")) {
			is_oauth2 = true;
		}	
		else if (0 == strcasecmp(pauthtype, "none")) {
			is_none = true;
		}	
		else {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : field \'auth_type\' value specfied \'%s\' is invalid: "
								"Specify auth_type as any of \'login\', \'oauth2\', \'cram_md5\' or \'none\' for no authentication", pauthtype);
		}	

		it = jval.FindMember("user");

		if (it == jval.MemberEnd()) {
			if (!is_none) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Missing mandatory field \'user\' : Please specify the sender email as \'user\'");
			}
		}	
		else if (false == it->value.IsString() || !it->value.GetStringLength()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : field \'user\' not a valid String type");
		}	
		else {
			puser = it->value.GetString();
		}	

		if (!is_none) {
			writer.KeyConst("auth");
			writer.StartObject();

			if (is_login || is_cram) {
				it = jval.FindMember("password");

				if (it == jval.MemberEnd()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Missing mandatory field \'password\'");
				}	
				else if (false == it->value.IsString() || !it->value.GetStringLength()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : field \'password\' not a valid String type");
				}	

				writer.KeyConst("type");

				if (!is_cram) {
					writer.StringConst("login");
				}
				else {
					writer.String("custom");

					writer.KeyConst("method");
					writer.StringConst("CRAM-MD5");
				}	

				writer.KeyConst("user");
				writer.String(puser);

				writer.KeyConst("pass");
				writer.String(it->value.GetString(), it->value.GetStringLength());
			}
			else { 
				/* oauth2 */

				writer.KeyConst("type");
				writer.StringConst("OAuth2");

				writer.KeyConst("user");
				writer.String(puser);

				it = jval.FindMember("clientid");

				if (it == jval.MemberEnd()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Missing mandatory field \'clientid\' for oauth2 type");
				}	
				else if (false == it->value.IsString() || !it->value.GetStringLength()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : field \'clientid\' not a valid String type");
				}	

				writer.KeyConst("clientId");
				writer.String(it->value.GetString(), it->value.GetStringLength());

				it = jval.FindMember("client_secret");

				if (it == jval.MemberEnd()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Missing mandatory field \'client_secret\' for oauth2 type");
				}	
				else if (false == it->value.IsString() || !it->value.GetStringLength()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : field \'client_secret\' not a valid String type");
				}	

				writer.KeyConst("clientSecret");
				writer.String(it->value.GetString(), it->value.GetStringLength());

				it = jval.FindMember("access_url");

				if (it == jval.MemberEnd()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Missing mandatory field \'access_url\' for oauth2 type : "
							"Please specify the URL for Token Generation e.g. for Gmail : https://accounts.google.com/o/oauth2/token");
				}	
				else if (false == it->value.IsString() || !it->value.GetStringLength()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : field \'access_url\' not a valid String type");
				}	

				writer.KeyConst("accessUrl");
				writer.String(it->value.GetString(), it->value.GetStringLength());

				bool				is_refresh = false;

				it = jval.FindMember("refresh_token");

				if (it != jval.MemberEnd() && it->value.IsString()) {
					writer.KeyConst("refreshToken");
					writer.String(it->value.GetString(), it->value.GetStringLength());

					is_refresh = true; 
				}	

				it = jval.FindMember("access_token");

				if ((it == jval.MemberEnd() || !it->value.IsString()) && !is_refresh) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Missing field \'access_token\' for oauth2 type");
				}	
				else if (it != jval.MemberEnd() && it->value.IsString()) {

					writer.KeyConst("accessToken");
					writer.String(it->value.GetString(), it->value.GetStringLength());

					uint64_t		exp = 0;
					
					it = jval.FindMember("expires_in");

					if (it != jval.MemberEnd() && it->value.IsUint64()) {
						exp = it->value.GetUint64();

						if (tcreate > 0 && exp > (uint64_t)tcreate * 1000) {
							// Looks like its expires_at instead of expires_in
						}
						else {
							exp += tcreate * 1000;
						}	
					}	

					it = jval.FindMember("expires_at");

					if (it != jval.MemberEnd() && it->value.IsUint64()) {
						exp = it->value.GetUint64();

						if (exp <= 10 * GY_SEC_PER_YEAR) {
							// Looks like its expires_in instead of expires_at
							exp = exp * 1000 + tcreate * 1000;
						}
					}	

					if (exp) {
						writer.KeyConst("expires");
						writer.Uint64(exp);
					}	
				}	
			}	
				
			writer.EndObject();	

			if (is_cram) {
				writer.KeyConst("customAuth");
				writer.StartObject();
				
				writer.KeyConst("CRAM-MD5");
				writer.StringConst("nodemailerCramMd5");

				writer.EndObject();
			}
		}	

		writer.KeyConst("pool");	

		it = jval.FindMember("use_pool");
		
		if (it != jval.MemberEnd() && it->value.IsBool()) {
			writer.Bool(it->value.GetBool());
		}	
		else {
			writer.Bool(true);
		}	

		it = jval.FindMember("proxy_url");

		if (it != jval.MemberEnd() && it->value.IsString() && it->value.GetStringLength()) {
			const char			*proxyurl;

			proxyurl = it->value.GetString();

			if ((memcmp(proxyurl, "http://", GY_CONST_STRLEN("http://"))) && (memcmp(proxyurl, "https://", GY_CONST_STRLEN("https://"))) &&
				(memcmp(proxyurl, "socks5://", GY_CONST_STRLEN("socks5://"))) && (memcmp(proxyurl, "socks4://", GY_CONST_STRLEN("socks4://")))
				&& (memcmp(proxyurl, "socks://", GY_CONST_STRLEN("socks://")))) {
				
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Invalid \'proxy_url\' specified \'%s\' : "
						"Use as in http://proxy-host:1234 or socks5://socks-host:1234", proxyurl);
			}	
			if (nullptr == strchr(proxyurl, ':')) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Invalid \'proxy_url\' specified \'%s\' : "
						"Specify port as well as host as in http://proxy-host:1234 or socks5://socks-host:1234", proxyurl);
			}	

			writer.KeyConst("proxy");
			writer.String(proxyurl, it->value.GetStringLength());
		}	

		writer.EndObject();	// connection

	}

override1 :

	writer.KeyConst("message");
	writer.StartObject();
	
	it = jval.FindMember("from"); 
	
	if (it == jval.MemberEnd()) {
		if (!is_override) {
			if (!puser) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Missing sender email : Please specify either of \'user\' or \'from\' fields");
			}	

			if (nullptr == strchr(puser, '@')) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : Missing sender email : Please specify \'from\' field");
			}	

			writer.KeyConst("from");
			writer.String(puser);
		}
	}
	else if (false == it->value.IsString()) {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : \'from\' not in String format");
	}	
	else if (it->value.GetStringLength()) {
		const char		*pfrom = it->value.GetString();

		if (nullptr == strchr(pfrom, '@')) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : \'from\' field \'%s\' not in email format : Please specify sender email", pfrom);
		}

		writer.KeyConst("from");
		writer.String(pfrom, it->value.GetStringLength());
	}	

	bool			is_to = false, is_cc = false, is_bcc = false;

	it = jval.FindMember("to"); 
	
	if (it != jval.MemberEnd() && it->value.IsString() && it->value.GetStringLength()) {
		is_to = true;

		writer.KeyConst("to");
		writer.String(it->value.GetString(), it->value.GetStringLength());
	}

	it = jval.FindMember("cc"); 
	
	if (it != jval.MemberEnd() && it->value.IsString() && it->value.GetStringLength()) {
		is_cc = true;

		writer.KeyConst("cc");
		writer.String(it->value.GetString(), it->value.GetStringLength());
	}

	it = jval.FindMember("bcc"); 
	
	if (it != jval.MemberEnd() && it->value.IsString() && it->value.GetStringLength()) {
		is_bcc = true;

		writer.KeyConst("bcc");
		writer.String(it->value.GetString(), it->value.GetStringLength());
	}

	if (!is_to && !is_cc && !is_bcc && !is_override) {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : One of \'to\', \'cc\' or \'bcc\' field not found : "
							"Please specify Receipient email");
	}

	writer.KeyConst("gy_subject_prefix");

	it = jval.FindMember("subject_prefix"); 
	
	if (it != jval.MemberEnd() && it->value.IsString() && it->value.GetStringLength()) {
		writer.String(it->value.GetString(), it->value.GetStringLength());
	}
	else {
		writer.StringConst("Gyeeta Alert");
	}

	it = jval.FindMember("headers"); 
	
	if (it != jval.MemberEnd()) {
		if (false == it->value.IsObject()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Email Alert Action Config : \'headers\' field must be JSON Object type : "
							"e.g. { \"x-processed\" : true, \"x-mykeys\" : [ \"val1\", \"val2\" ] }");
		}	

		writer.KeyConst("headers");
		it->value.Accept(writer);
	}

	it = jval.FindMember("send_text");
		
	if (it != jval.MemberEnd() && it->value.IsBool()) {
		if (true == it->value.GetBool()) {
			writer.KeyConst("gy_send_text");	
			writer.Bool(true);
		}
	}	

	writer.EndObject();	// message
	
	writer.EndObject();
}	

void ALERT_ACTION::verify_slack_config(const GEN_JSON_VALUE & jval, STACK_JSON_WRITER<4096, 2048> & writer, bool is_override, time_t tcreate)
{
	/*
	 * We support Slack Messaging using either an Incoming Webhook or using Chat PostMessage 
	 * 
	 * List of Slack options :
	 *
	 * api_url 			: Mandatory : Can be a Webhook URL such as https://hooks.slack.com/services/CCC/XYZ/ABC or Chat PostMessage URL https://slack.com/api/chat.postMessage
	 * channel			: Optional for Webhook URLs and Mandatory for Chat PostMessage URL : Can be the Channel ID or name
	 * access_token			: Mandatory only for Chat PostMessage URL : e.g. xoxb-1234-abcd-abcd : Must have chat:write Scope
	 * proxy_url			: Optional : HTTP/HTTPS Proxies allowed : e.g. 'http://proxy-host:1234'
	 * tls_reject_unauthorized 	: Optional : If set to false will skip validation of invalid or self-signed TLS certificates
	 *
	 * api_url cannot be overridden
	 */

	JSON_MEM_CONST_ITER		it;
	bool				is_chatpost = false;
	
	writer.StartObject();

	it = jval.FindMember("api_url");

	if (it == jval.MemberEnd()) {
		if (!is_override) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Slack Alert Action Config : Missing mandatory field \'api_url\' : Please specify the Slack Webhook or Chat PostMessage URL");
		}
	}	
	else if (false == it->value.IsString() || !it->value.GetStringLength()) {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Slack Alert Action Config : Field \'api_url\' not a valid String Type : Please specify the Slack Webhook or Chat PostMessage URL");
	}	
	else {
		if (is_override) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Slack Action Override : Cannot override \'api_url\' in Alert Action : Please use a new Action Definition instead");
		}	

		if (strcasestr(it->value.GetString(), "chat.PostMessage")) {
			is_chatpost = true;

			writer.KeyConst("is_chatpost");
			writer.Bool(true);
		}

		writer.KeyConst("api_url");
		writer.String(it->value.GetString(), it->value.GetStringLength());
	}

	it = jval.FindMember("channel");

	if (it != jval.MemberEnd() && it->value.IsString() && it->value.GetStringLength()) {
		writer.KeyConst("channel");
		writer.String(it->value.GetString(), it->value.GetStringLength());
	}	
	else if (is_chatpost) {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Slack Alert Action Config : Field \'channel\' not specified for Chat PostMessage URL : Please specify the Slack Channel Name or ID");
	}	

	it = jval.FindMember("access_token");

	if (it != jval.MemberEnd() && it->value.IsString() && it->value.GetStringLength()) {
		writer.KeyConst("access_token");
		writer.String(it->value.GetString(), it->value.GetStringLength());
	}	
	else if (is_chatpost) {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Slack Alert Action Config : Field \'access_token\' not specified for Chat PostMessage URL : Please specify the Slack App OAuth Token");
	}	

	it = jval.FindMember("proxy_url");

	if (it != jval.MemberEnd() && it->value.IsString() && it->value.GetStringLength()) {
		const char			*proxyurl;

		proxyurl = it->value.GetString();

		if ((memcmp(proxyurl, "http://", GY_CONST_STRLEN("http://"))) && (memcmp(proxyurl, "https://", GY_CONST_STRLEN("https://")))) { 
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Slack Alert Action Config : Invalid \'proxy_url\' specified \'%s\' : "
					"Use as in http://proxy-host:1234 or https://proxy-host:2345", proxyurl);
		}	

		if (nullptr == strchr(proxyurl, ':')) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Slack Alert Action Config : Invalid \'proxy_url\' specified \'%s\' : "
					"Specify port as well as host as in http://proxy-host:1234 or https://proxy-host:2345", proxyurl);
		}	

		writer.KeyConst("proxy_url");
		writer.String(proxyurl, it->value.GetStringLength());
	}	

	it = jval.FindMember("tls_reject_unauthorized");

	if (it != jval.MemberEnd() && it->value.IsBool()) {
		if (false == it->value.GetBool()) {
			writer.KeyConst("tls_reject_unauthorized");
			writer.Bool(false);
		}
	}	

	writer.EndObject();
}	

void ALERT_ACTION::verify_pagerduty_config(const GEN_JSON_VALUE & jval, STACK_JSON_WRITER<4096, 2048> & writer, bool is_override, time_t tcreate)
{
	/*
	 * Gyeeta uses Pagerduty Events API v2 incidents. Grouped Alerts will be sent as multiple individual Pager incidents...
	 *
	 * List of Pagerduty config params sent by Shyama :
	 *
	 * api_url 			: Optional : Default is https://events.pagerduty.com/v2/enqueue
	 * routing_key			: Mandatory : The Integration Key for Events API v2.
	 * proxy_url			: Optional : HTTP/HTTPS Proxies allowed : e.g. 'http://proxy-host:1234'
	 * tls_reject_unauthorized 	: Optional : If set to false will skip validation of invalid or self-signed TLS certificates
	 *
	 * api_url cannot be overridden
	 */

	JSON_MEM_CONST_ITER		it;
	
	writer.StartObject();

	it = jval.FindMember("api_url");

	if (it == jval.MemberEnd()) {
		if (!is_override) {
			writer.KeyConst("api_url");
			writer.StringConst("https://events.pagerduty.com/v2/enqueue");
		}
	}	
	else if (false == it->value.IsString() || !it->value.GetStringLength()) {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Pagerduty Alert Action Config : Field \'api_url\' not a valid String Type : Please specify the Pagerduty Events API v2 URL");
	}	
	else {
		if (is_override) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Pagerduty Action Override : Cannot override \'api_url\' in Alert Action : Please use a new Action Definition instead");
		}	

		writer.KeyConst("api_url");
		writer.String(it->value.GetString(), it->value.GetStringLength());
	}

	it = jval.FindMember("routing_key");

	if (it != jval.MemberEnd() && it->value.IsString() && it->value.GetStringLength()) {
		writer.KeyConst("routing_key");
		writer.String(it->value.GetString(), it->value.GetStringLength());
	}	
	else {
		GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Pagerduty Alert Action Config : Field \'routing_key\' not specified : Please specify the Events API v2 Integration Key");
	}	

	it = jval.FindMember("proxy_url");

	if (it != jval.MemberEnd() && it->value.IsString() && it->value.GetStringLength()) {
		const char			*proxyurl;

		proxyurl = it->value.GetString();

		if ((memcmp(proxyurl, "http://", GY_CONST_STRLEN("http://"))) && (memcmp(proxyurl, "https://", GY_CONST_STRLEN("https://")))) { 
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Pagerduty Alert Action Config : Invalid \'proxy_url\' specified \'%s\' : "
					"Use as in http://proxy-host:1234 or https://proxy-host:2345", proxyurl);
		}	

		if (nullptr == strchr(proxyurl, ':')) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Pagerduty Alert Action Config : Invalid \'proxy_url\' specified \'%s\' : "
					"Specify port as well as host as in http://proxy-host:1234 or https://proxy-host:2345", proxyurl);
		}	

		writer.KeyConst("proxy_url");
		writer.String(proxyurl, it->value.GetStringLength());
	}	

	it = jval.FindMember("tls_reject_unauthorized");

	if (it != jval.MemberEnd() && it->value.IsBool()) {
		if (false == it->value.GetBool()) {
			writer.KeyConst("tls_reject_unauthorized");
			writer.Bool(false);
		}
	}	

	writer.EndObject();
}	

void ALERT_ACTION::verify_webhook_config(const GEN_JSON_VALUE & jval, STACK_JSON_WRITER<4096, 2048> & writer, bool is_override, time_t tcreate)
{
	/*
	 * List of Webhook options :
	 *
	 * api_url 			: Mandatory : The Webhook URL to send the HTTP Post to
	 *
	 * auth_type 			: Mandatory : 4 valid types none, basic_auth, bearer and oauth2 : If 'none' is specified no authentication will be done.
	 *
	 * For auth_type basic_auth :
	 * username			: Mandatory if auth_type is basic_auth Ignored otherwise
	 * password			: Mandatory if auth_type is basic_auth Ignored otherwise
	 * 
	 * For auth_type bearer :
	 * bearer_token			: Mandatory if auth_type is bearer Ignored otherwise
	 *
	 * For auth_type oauth2 (Only Client Credentials grant type supported. Both Authorization Header and Body format params supported) :
	 * clientid			: Mandatory : registered client id of the application
	 * client_secret		: Mandatory : registered client secret of the application
	 * access_url			: Mandatory : Endpoint for token generation
	 * refresh_token		: Optional : If provided then Gyeeta will use it to generate a new access token if existing one expires or fails
	 * access_token			: Optional : Indicates an existing OAuth2 Access Token
	 * expires_in			: Optional : Indicates Time in sec from current time when the access_token will expire (expires at current + this value in sec)
	 * expires_at			: Optional : Indicates Time in msec from 1970 when the access_token will expire (expires at this value in msec)
	 * scope			: Optional : Space or comma separated string containing list of scopes
	 * use_auth_header		: Optional : Default true : Indicates whether to send the Client ID/Secret using Authentication Header or Form Body Params
	 * 
	 * Following options can be overriden :
	 *
	 * proxy_url			: Optional : HTTP/HTTPS Proxies allowed : e.g. 'http://proxy-host:1234'
	 * tls_reject_unauthorized 	: Optional : If set to false will skip validation of invalid or self-signed TLS certificates
	 * headers			: Optional : Custom Headers to be sent : Needs to be an Object as in "headers" : { "x-processed" : true, "x-mykeys" : [ "val1", "val2" ] }
	 * data_format			: Optional : Format of the payload : Currently only 1 format supported : generic. 
	 *
	 */
	 
	 static constexpr const char	*nonoverrides[] 
	 		{ 	
				"api_url", "auth_type", "username", "password", "bearer_token",
				"clientid", "client_secret", "access_url", "refresh_token", "access_token", "expires_in", "expires_at", "scope",
	 		};

	const char			*puser = nullptr;
	JSON_MEM_CONST_ITER		it;
	
	writer.StartObject();

	if (is_override) {
		for (const char * pkey : nonoverrides) {
			if (auto it = jval.FindMember(pkey); it != jval.MemberEnd()) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Action Override : Cannot override connection related field \'%s\' : "
					"Only specific fields such as \'data_format\', \'tls_reject_unauthorized\' can be overridden", pkey);
			}	
		}

		goto override1;
	}	
	else {
		it = jval.FindMember("api_url");

		if (it == jval.MemberEnd()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : Missing mandatory field \'api_url\' : Please specify the Webhook URL");
		}
		else if (false == it->value.IsString() || !it->value.GetStringLength()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : \'api_url\' not a valid String type : Please specify the Webhook URL");
		}	

		writer.KeyConst("api_url");
		writer.String(it->value.GetString(), it->value.GetStringLength());

		it = jval.FindMember("auth_type");

		if (it == jval.MemberEnd()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : Missing mandatory field \'auth_type\' : "
								"Specify auth_type as any of \'basic_auth\', \'oauth2\', \'bearer\' or \'none\' for no authentication");
		}	
		else if (false == it->value.IsString() || !it->value.GetStringLength()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : field \'auth_type\' not a valid String type : "
								"Specify auth_type as any of \'basic_auth\', \'oauth2\', \'bearer\' or \'none\' for no authentication");
		}	
		
		const char			*pauthtype = nullptr;
		bool				is_basic = false, is_bearer = false, is_oauth2 = false, is_none = false;

		pauthtype = it->value.GetString();

		writer.KeyConst("auth_type");

		if (0 == strcasecmp(pauthtype, "basic_auth")) {
			writer.StringConst("basic_auth");
			is_basic = true;
		}	
		else if (0 == strcasecmp(pauthtype, "bearer")) {
			writer.StringConst("bearer");
			is_bearer = true;
		}	
		else if (0 == strcasecmp(pauthtype, "oauth2")) {
			writer.StringConst("oauth2");
			is_oauth2 = true;
		}	
		else if (0 == strcasecmp(pauthtype, "none")) {
			writer.StringConst("none");
			is_none = true;
		}	
		else {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : field \'auth_type\' value specfied \'%s\' is invalid: "
								"Specify auth_type as any of \'basic_auth\', \'oauth2\', \'bearer\' or \'none\' for no authentication", pauthtype);
		}	

		if (!is_none) {
			if (is_basic) {
				it = jval.FindMember("username");

				if (it == jval.MemberEnd()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : Missing mandatory field \'username\'");
				}	
				else if (false == it->value.IsString() || !it->value.GetStringLength()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : field \'username\' not a valid String type");
				}	

				writer.KeyConst("username");
				writer.String(it->value.GetString(), it->value.GetStringLength());

				it = jval.FindMember("password");

				if (it == jval.MemberEnd()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : Missing mandatory field \'password\' for auth_type basic_auth");
				}	
				else if (false == it->value.IsString() || !it->value.GetStringLength()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : field \'password\' not a valid String type");
				}	

				writer.KeyConst("password");
				writer.String(it->value.GetString(), it->value.GetStringLength());
			}
			else if (is_bearer) {
				it = jval.FindMember("bearer_token");

				if (it == jval.MemberEnd()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : Missing mandatory field \'bearer_token\' for auth_type bearer");
				}	
				else if (false == it->value.IsString() || !it->value.GetStringLength()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : field \'bearer_token\' not a valid String type");
				}	

				writer.KeyConst("bearer_token");
				writer.String(it->value.GetString(), it->value.GetStringLength());
			}
			else if (is_oauth2) {

				it = jval.FindMember("clientid");

				if (it == jval.MemberEnd()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : Missing mandatory field \'clientid\' for oauth2 type");
				}	
				else if (false == it->value.IsString() || !it->value.GetStringLength()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : field \'clientid\' not a valid String type");
				}	

				writer.KeyConst("clientId");
				writer.String(it->value.GetString(), it->value.GetStringLength());

				it = jval.FindMember("client_secret");

				if (it == jval.MemberEnd()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : Missing mandatory field \'client_secret\' for oauth2 type");
				}	
				else if (false == it->value.IsString() || !it->value.GetStringLength()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : field \'client_secret\' not a valid String type");
				}	

				writer.KeyConst("client_secret");
				writer.String(it->value.GetString(), it->value.GetStringLength());

				it = jval.FindMember("access_url");

				if (it == jval.MemberEnd()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : Missing mandatory field \'access_url\' for oauth2 type : "
							"Please specify the URL for Token Generation e.g. https://accounts.google.com/o/oauth2/token");
				}	
				else if (false == it->value.IsString() || !it->value.GetStringLength()) {
					GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : field \'access_url\' not a valid String type");
				}	

				writer.KeyConst("access_url");
				writer.String(it->value.GetString(), it->value.GetStringLength());

				bool				is_refresh = false;

				it = jval.FindMember("refresh_token");

				if (it != jval.MemberEnd() && it->value.IsString() && it->value.GetStringLength()) {
					writer.KeyConst("refresh_token");
					writer.String(it->value.GetString(), it->value.GetStringLength());

					is_refresh = true; 
				}	

				it = jval.FindMember("access_token");

				if (it != jval.MemberEnd() && it->value.IsString() && it->value.GetStringLength()) {

					writer.KeyConst("access_token");
					writer.String(it->value.GetString(), it->value.GetStringLength());

					uint64_t		exp = 0;
					
					it = jval.FindMember("expires_in");

					if (it != jval.MemberEnd() && it->value.IsUint64()) {
						exp = it->value.GetUint64();

						if (tcreate > 0 && exp > (uint64_t)tcreate * 1000) {
							// Looks like its expires_at instead of expires_in
						}
						else {
							exp += tcreate * 1000;
						}	
					}	

					it = jval.FindMember("expires_at");

					if (it != jval.MemberEnd() && it->value.IsUint64()) {
						exp = it->value.GetUint64();

						if (exp <= 10 * GY_SEC_PER_YEAR) {
							// Looks like its expires_in instead of expires_at
							exp = exp * 1000 + tcreate * 1000;
						}
					}	

					if (exp) {
						writer.KeyConst("expires_at");
						writer.Uint64(exp);
					}	
				}	

				it = jval.FindMember("scope");

				if (it != jval.MemberEnd() && it->value.IsString() && it->value.GetStringLength()) {
					writer.KeyConst("scope");
					writer.String(it->value.GetString(), it->value.GetStringLength());
				}	

				writer.KeyConst("use_auth_header");

				it = jval.FindMember("use_auth_header");

				if (it != jval.MemberEnd() && it->value.IsBool()) {
					writer.Bool(it->value.GetBool());
				}	
				else {
					writer.Bool(true);
				}	

			}	
		}	

	}

override1 :
	/*
	 * Following options can be overridden
	 */

	it = jval.FindMember("proxy_url");

	if (it != jval.MemberEnd() && it->value.IsString() && it->value.GetStringLength()) {
		const char			*proxyurl;

		proxyurl = it->value.GetString();

		if ((memcmp(proxyurl, "http://", GY_CONST_STRLEN("http://"))) && (memcmp(proxyurl, "https://", GY_CONST_STRLEN("https://")))) { 
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : Invalid \'proxy_url\' specified \'%s\' : "
					"Use as in http://proxy-host:1234 or https://proxy-host:2345", proxyurl);
		}	

		if (nullptr == strchr(proxyurl, ':')) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : Invalid \'proxy_url\' specified \'%s\' : "
					"Specify port as well as host as in http://proxy-host:1234 or https://proxy-host:2345", proxyurl);
		}	

		writer.KeyConst("proxy_url");
		writer.String(proxyurl, it->value.GetStringLength());
	}	

	it = jval.FindMember("tls_reject_unauthorized");

	if (it != jval.MemberEnd() && it->value.IsBool()) {
		if (false == it->value.GetBool()) {
			writer.KeyConst("tls_reject_unauthorized");
			writer.Bool(false);
		}
	}	

	it = jval.FindMember("headers"); 
	
	if (it != jval.MemberEnd()) {
		if (false == it->value.IsObject()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Webhook Alert Action Config : \'headers\' field must be JSON Object type : "
							"e.g. { \"x-processed\" : true, \"x-mykeys\" : [ \"val1\", \"val2\" ] }");
		}	

		writer.KeyConst("headers");
		it->value.Accept(writer);
	}

	it = jval.FindMember("data_format");

	if (it != jval.MemberEnd() && it->value.IsString() && it->value.GetStringLength()) {
		writer.KeyConst("data_format");
		writer.String(it->value.GetString(), it->value.GetStringLength());
	}	
	
	writer.EndObject();
}	

ADEF_ACTION::ADEF_ACTION(const intrusive_ptr<ALERT_ACTION> & actionshr, const GEN_JSON_VALUE * pjval, SUBSYS_CLASS_E asubsys, const char *subsys_str, \
				const JSON_DB_MAPPING **pcolmap, uint32_t nmap_fields, bool is_multihost, bool is_last_elem)
	: actionshr_(actionshr)
{
	if (!actionshr_) {
		GY_THROW_EXCEPT_CODE(ERR_SERV_ERROR, "Internal Error : Alert Object invalid for Alert Definition");
	}

	send_resolved_ = actionshr_->send_resolved_;

	if (!pjval) {
		if (!is_last_elem) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Definition as intermediate Alert Action with no \'match\' or \'continue\'. All subsequent Actions will always be ignored.");
		}	
		return;
	}

	const auto		& jval = *pjval;

	if (auto it = jval.FindMember("config"); (it != jval.MemberEnd())) {
		if (false == it->value.IsObject()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Alert Action JSON : config field not of Object Type");
		}	

		STACK_JSON_WRITER<4096, 2048>		writer;

		switch (actionshr_->acttype_) {
		
		case ACTION_NULL		:	ALERT_ACTION::verify_null_config(it->value, writer, true /* is_override */); break; 

		case ACTION_EMAIL		:	ALERT_ACTION::verify_email_config(it->value, writer, true /* is_override */); break; 

		case ACTION_SLACK		:	ALERT_ACTION::verify_slack_config(it->value, writer, true /* is_override */); break; 

		case ACTION_PAGERDUTY		:	ALERT_ACTION::verify_pagerduty_config(it->value, writer, true /* is_override */); break; 

		case ACTION_WEBHOOK		:	ALERT_ACTION::verify_webhook_config(it->value, writer, true /* is_override */); break; 

		default				:	break;

		}	

		newconfig_.assign(writer.get_string(), writer.get_size());
	}

	if (auto it = jval.FindMember("send_resolved"); (it != jval.MemberEnd())) {
		if (false == it->value.IsBool()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Alert Action JSON : send_resolved field not of Boolean Type");
		}	

		send_resolved_ = it->value.GetBool();
	}

	if (!is_last_elem) {
		if (auto it = jval.FindMember("continue"); (it != jval.MemberEnd())) {
			if (false == it->value.IsBool()) {
				GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Alert Action JSON : continue field not of Boolean Type");
			}	

			continue_ = it->value.GetBool();
		}
	}

	if (auto it = jval.FindMember("match"); (it != jval.MemberEnd())) {
		if (false == it->value.IsString()) {
			GY_THROW_EXCEPT_CODE(ERR_INVALID_REQUEST, "Invalid Alert Action JSON : match field not of String Type");
		}	

		if (nmap_fields > MAX_MULTI_HOST_COLUMN_LIST) {
			GY_THROW_EXCEPT_CODE(ERR_SERV_ERROR, "Number of columns specified for Action Definition %u exceeds maximum allowed %lu", nmap_fields, MAX_COLUMN_LIST);
		}

		/*
		 * NOTE : We allow only Action match to reference actual subsystem fields.
		 */
		const JSON_DB_MAPPING 	*subsys_col_arr[GY_ARRAY_SIZE(json_db_alerts_arr) + nmap_fields];
		uint32_t		ncol_arr = 0;

		for (size_t i = 0; i < GY_ARRAY_SIZE(json_db_alerts_arr); ++i) {
			subsys_col_arr[ncol_arr++] = json_db_alerts_arr + i;
		}	

		for (size_t i = 0; i < nmap_fields; ++i) {
			subsys_col_arr[ncol_arr++] = pcolmap[i];
		}	
		
		match_ = CRITERIA_SET(it->value.GetString(), it->value.GetStringLength(), asubsys, subsys_str, subsys_col_arr, ncol_arr, 
						nullptr /* pextpool */, is_multihost, true /* allocregex */);
	}
}	

ALERT_STATE_E astate_from_string(const char *pstr, uint32_t len) noexcept
{
	const char		*pend = pstr + len;

	while (pstr < pend && is_space_tab(*pstr)) pstr++;
	
	if (pstr == pend) {
		return ASTATE_UNKNOWN;
	}

	switch (tolower(*pstr)) {

	case 'g' : 
		if (0 == strncasecmp(pstr, "groupwait", GY_CONST_STRLEN("groupwait"))) {
			return ASTATE_GROUP_WAIT;
		}

		break;

	case 's' :
		if (0 == strncasecmp(pstr, "suppressed", GY_CONST_STRLEN("suppressed"))) {
			return ASTATE_SUPPRESSED;
		}

		break;

	case 'a' : 
		if (0 == strncasecmp(pstr, "active", GY_CONST_STRLEN("active"))) {
			return ASTATE_ACTIVE;
		}	
		else if (0 == strncasecmp(pstr, "acked", GY_CONST_STRLEN("acked"))) {
			return ASTATE_ACKED;
		}	
		
		break;

	case 'r' :
		if (0 == strncasecmp(pstr, "resolved", GY_CONST_STRLEN("resolved"))) {
			return ASTATE_RESOLVED;
		}

		break;

	case 'e' :
		if (0 == strncasecmp(pstr, "expired", GY_CONST_STRLEN("expired"))) {
			return ASTATE_EXPIRED;
		}

		break;


	default :
		break;
	}

	return ASTATE_UNKNOWN;
}	

ADEF_SEVERITY_E severity_from_string(const char *pstr, uint32_t len) noexcept
{
	const char		*pend = pstr + len;

	while (pstr < pend && is_space_tab(*pstr)) pstr++;
	
	if (pstr == pend) {
		return ASEVERITY_UNKNOWN;
	}

	switch (tolower(*pstr)) {

	case 'c' : 
		if (0 == strncasecmp(pstr, "critical", GY_CONST_STRLEN("critical"))) {
			return ASEVERITY_CRITICAL;
		}

		break;

	case 'w' : 
		if (0 == strncasecmp(pstr, "warning", GY_CONST_STRLEN("warning"))) {
			return ASEVERITY_WARNING;
		}	

		break;

	case 'i' :
		if (0 == strncasecmp(pstr, "info", GY_CONST_STRLEN("info"))) {
			return ASEVERITY_INFO;
		}

		break;

	case 'd' : 
		if (0 == strncasecmp(pstr, "debug", GY_CONST_STRLEN("debug"))) {
			return ASEVERITY_DEBUG;
		}	
		
		break;

	default :
		break;
	}

	return ASEVERITY_UNKNOWN;
}	


ALERT_SEVERITY::ALERT_SEVERITY(const GEN_JSON_VALUE & jdoc, SUBSYS_CLASS_E asubsys, const char *subsys_str, const JSON_DB_MAPPING **pcolmap, uint32_t nmap_fields, bool is_multihost)
{
	ADEF_SEVERITY_E 	severity;

	if (jdoc.IsString()) {
		severity = severity_from_string(jdoc.GetString(), jdoc.GetStringLength());	

		if (severity == ASEVERITY_UNKNOWN) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Severity : Severity specified \'%s\' not a valid severity", jdoc.GetString());
		}	
		
		fseverity_ = severity;
		return;
	}	
	else if (false == jdoc.IsArray()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Severity : Not of a String or JSON Array type");
	}	

	if (0 == jdoc.Size()) {
		fseverity_ = ASEVERITY_INFO;
		return;
	}	

	dynvec_.reserve(jdoc.Size());

	for (uint32_t i = 0; i < jdoc.Size(); ++i) {
		if (false == jdoc[i].IsObject()) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Severity Element %u within JSON Array : Not of a JSON Object type", i);
		}	
		
		const auto		& obj = jdoc[i].GetObject();

		auto 			aiter = obj.FindMember("level"); 

		if ((aiter != obj.MemberEnd()) && (aiter->value.IsString())) {
			severity = severity_from_string(aiter->value.GetString(), aiter->value.GetStringLength());	

			if (severity == ASEVERITY_UNKNOWN) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Severity : Severity specified \'%s\' not a valid severity", aiter->value.GetString());
			}	
		}
		else {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Severity Element #%u : \'level\' field not seen", i + 1);
		}	

		aiter = obj.FindMember("match");

		if (aiter != obj.MemberEnd()) {
			if (false == aiter->value.IsString()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Severity Element #%u : \'match\' field not of a String Type", i + 1);
			}	

			dynvec_.emplace_back(severity, aiter->value.GetString(), aiter->value.GetStringLength(), asubsys, subsys_str, pcolmap, nmap_fields, is_multihost);
		}
		else if (i + 1 == jdoc.Size()) {
			// Fallback severity
			dynvec_.emplace_back(severity);
		}
		else {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Severity Element #%u : \'match\' field not seen and element is not the last...", i + 1);
		}	
	}	
}	

ADEF_SEVERITY_E ALERT_SEVERITY::get_severity(const AlertStatFilter & filter) const
{
	for (const auto & dyn : dynvec_) {
		if (CRIT_FAIL != filter.filter_match(dyn.match_)) {
			return dyn.severity_;
		}	
	}	

	return fseverity_;
}	

ALERT_TMPL_STRING::ALERT_TMPL_STRING(const char *pstr, uint32_t sz, const JSON_DB_MAPPING **pcolmap, uint32_t nmap_fields)
	: lenstr_(sz)
{
	if (sz == 0) {
		return;
	}	

	if (sz > 2048) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Template String \'%s\' Length Too large : Max 2048 bytes allowed", CHAR_BUF<128>(pstr, sz).get());
	}

	str_ = std::make_unique<char []>(sz + 1);
	std::memcpy(str_.get(), pstr, sz);
	*(str_.get() + sz) = 0;

	char			*pstart = str_.get(), *pend = pstart + sz, *ptmp = pstart, *ptmp2, *pfield, *pfend, *ptstart, *ptend;
	uint32_t		nalert_fields = GY_ARRAY_SIZE(json_db_alerts_arr);

	do {
		ptmp2 = (char *)memchr(ptmp, '{', pend - ptmp);

		if (!ptmp2 || ptmp2 + 3 >= pend) {
			break;
		}	

		if (ptmp2[1] != '{') {
			ptmp = ptmp2 + 1;
			continue;
		}	
			
		ptmp = ptmp2;

		ptmp[0] = ' ';
		ptmp[1] = '[';
	
		ptmp += 2;

		ptstart = ptmp;
		pfield = ptmp;

		ptmp2 = (char *)memmem(ptmp, pend - ptmp, "}}", 2);

		if (!ptmp2) {
			break;
		}	
		
		ptend = ptmp2 + 1;
		pfend = ptmp2 - 1;

		/*ptmp2[0] = ' ';*/
		/*ptmp2[1] = ' ';*/

		if (pfield < pfend) {
			const JSON_DB_MAPPING	*pcol;
			bool			is_alertdata;

			while (pfield < pfend && is_space_tab(*pfield)) pfield++;

			ptmp = pfield;

			while (ptmp <= pfend && !is_space_tab(*ptmp)) ptmp++;
			
			pfend = ptmp;

			if (pfield < pfend) {
				if ((pcol = get_jsoncrc_mapping(pfield, pfend - pfield, pcolmap, nmap_fields))) {
					is_alertdata = true;
				}	
				else if ((pcol = get_jsoncrc_mapping(pfield, pfend - pfield, json_db_alerts_arr, nalert_fields))) {
					is_alertdata = false;
				}	
				else {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Template String has an expression with an invalid field \'%s\' which is not found in column list : Example Use : {{ name }}", 
							CHAR_BUF<128>(pfield, pfend - pfield).get());
				}

				toffsets_.emplace_back(pcol, ptstart - pstart, ptend - pstart);
			}	
		}

next :
		ptmp = ptmp2 + 2;

	} while (ptmp + 3 < pend);
}	

void ALERT_TMPL_STRING::set_string(STR_WR_BUF & strbuf, const AlertStatFilter & filter) const
{
	if (!lenstr_) return;

	if (false == has_template()) {
		strbuf.append(str_.get(), lenstr_);
		return;
	}

	char			*pstart = str_.get(), *pend = pstart + lenstr_;
	uint16_t		last_end = 0;

	for (const auto & offset : toffsets_) {
		strbuf.append(pstart + last_end, offset.start_ > last_end ? offset.start_ - last_end : 0);

		filter.astat_field_to_string(offset.pcol_, strbuf);	

		strbuf << "] ";

		last_end = offset.end_ + 1;
	}	

	if (last_end < lenstr_) {
		strbuf.append(pstart + last_end, lenstr_ - last_end);
	}	
}	

ALERT_ANNOTATIONS::ALERT_ANNOTATIONS(const GEN_JSON_VALUE & jdoc, const JSON_DB_MAPPING **pcolmap, uint32_t nmap_fields)
{
	if (jdoc.IsString()) {
		const char		*pstr = jdoc.GetString();
		uint32_t		len = jdoc.GetStringLength();

		if (len) {
			if (len > 6000) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Alert Annotations String Length %u Too large : Max 6000 bytes allowed", len);
			}	

			annotvec_.reserve(1);
			
			annotvec_.emplace_back(pstr, len, pcolmap, nmap_fields);
		}
		
		return;
	}

	if (false == jdoc.IsArray()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Annotations : Not of a JSON Array or String type");
	}	

	if (0 == jdoc.Size()) {
		return;
	}	

	annotvec_.reserve(jdoc.Size());

	uint32_t			totallen = 0;

	for (uint32_t i = 0; i < jdoc.Size(); ++i) {
		if (false == jdoc[i].IsString()) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Annotations Element %u within JSON Array : Not of a String type", i + 1);
		}	
		
		const char		*pstr = jdoc[i].GetString();
		uint32_t		len = jdoc[i].GetStringLength();

		if (len) {
			totallen += len;

			if (totallen > 6000) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Alert Annotations Total String Length Too large : Max 6000 bytes allowed");
			}	

			annotvec_.emplace_back(pstr, len, pcolmap, nmap_fields);
		}
	}
}	

STRING_BUFFER<8192> ALERT_ANNOTATIONS::get_annotations(const AlertStatFilter & filter) const
{
	STRING_BUFFER<8192>		strbuf;

	if (annotvec_.size()) {
		strbuf << "[";
	}

	for (size_t i = 0; i < annotvec_.size(); ++i) {
		
		strbuf << "\"";
		annotvec_[i].set_string(strbuf, filter);
		strbuf << "\"";

		if (i + 1 < annotvec_.size()) {
			strbuf << ", ";
		}	
	}

	if (annotvec_.size()) {
		strbuf << "]";
	}

	return strbuf;
}

ALERT_GROUPBY::ALERT_GROUPBY(const GEN_JSON_VALUE & jdoc, SUBSYS_CLASS_E asubsys, const char *subsys_str, const JSON_DB_MAPPING **pcolmap, uint32_t nmap_fields)
{
	if (false == jdoc.IsArray()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Groupby : Not of a JSON Array type");
	}	

	if (0 == jdoc.Size()) {
		return;
	}	

	auto			*psubsys_stat = get_subsys_stats(asubsys);
	
	if (!psubsys_stat) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Group definition : Invalid Subsystem \'%s\' specified", subsys_str);
	}	

	bool			isalertname = false;

	groups_.reserve(jdoc.Size());

	for (uint32_t i = 0; i < jdoc.Size(); ++i) {
		if (false == jdoc[i].IsString()) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Groupby Element %u within JSON Array : Not of a String type", i + 1);
		}	
		
		const char		*pfield = jdoc[i].GetString();
		uint32_t		len = jdoc[i].GetStringLength();
		const JSON_DB_MAPPING	*pcol;

		if ((0 == strcmp(pfield, "...")) || (0 == strcmp(pfield, "none"))) {
			// No grouping to be done
			groups_.clear();
			return;
		}	
		else if (0 == strcmp(pfield, "alertname")) {
			isalertname = true;
		}	

		pcol = get_jsoncrc_mapping(pfield, len, pcolmap, nmap_fields);

		if (nullptr == pcol) {
			pcol = get_jsoncrc_mapping(pfield, len, json_db_alerts_arr, GY_ARRAY_SIZE(json_db_alerts_arr));

			if (!pcol) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Groupby Element %u : Field \'%s\' not part of Columns valid for this Alert definition",
								i + 1, pfield);
			}	
		}	

		groups_.emplace_back(pcol);
	}	

	/*
	 * Force alertname within the grouping 
	 */
	if (!isalertname) {
		const JSON_DB_MAPPING	*pcol;

		pcol = get_jsoncrc_mapping("alertname", GY_CONST_STRLEN("alertname"), json_db_alerts_arr, GY_ARRAY_SIZE(json_db_alerts_arr));
		
		assert(pcol);

		if (pcol) {
			groups_.emplace_back(pcol);
		}	
	}	
}	

bool ALERT_GROUPBY::get_group_str(const AlertStatFilter & filter, STR_WR_BUF & strbuf) const
{
	if (false == is_grouped()) {
		return false;
	}

	char				tbuf[2048];

	for (uint32_t i = 0; i < groups_.size() && strbuf.bytes_left() > 2; ++i) {
		auto			*pcol = groups_[i];

		if (!pcol) {
			continue;
		}	

		if (pcol->jsontype == JSON_STRING) {
			auto 		p = filter.astat_str_field(pcol, tbuf, sizeof(tbuf));

			if (p.second > 0) {
				strbuf << p << '_';
			}
		}
		else if (pcol->jsontype == JSON_NUMBER) {
			auto		n = filter.astat_num_field(pcol);

			if (n.is_valid()) {
				switch (n.get_type()) {
				
				case NUM_INT8 	: strbuf << n.get_int8() << '_'; break;

				case NUM_INT16 	: strbuf << n.get_int16() << '_'; break;

				case NUM_INT32	: strbuf << n.get_int32() << '_'; break;

				case NUM_INT64	: strbuf << n.get_int64() << '_'; break;

				case NUM_DOUBLE : strbuf << n.get_dbl() << '_'; break;

				default		: break;		

				}
			}
		}	
		else if (pcol->jsontype == JSON_BOOL) {
			auto 		b = filter.astat_bool_field(pcol);

			if (b.is_valid()) {
				strbuf << b.get() << '_';
			}	
		}	
	}

	if (strbuf.length()) {
		return true;
	}	
	else {
		return false;
	}	
}	

ALERTDEF::ALERTDEF(GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator,  const char *pdefstr, uint32_t szdef, uint32_t adefid, time_t tcurr, time_t tcreate, bool is_disabled)
	: ALERTDEF_COMMON(jdoc, allocator, adefid, tcurr), defstr_(pdefstr, szdef), tinit_(tcurr), tcreate_(tcreate)
{
	auto			*palertmgr = ALERTMGR::get_singleton();
	const char		*pname = name_.data();

	if (pthread_self() != palertmgr->thrid_) {
		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Internal Error : Alert Definition constructor for \'%s\' called from thread other than the Alert Manager", pname);
	}

	if (is_disabled) {
		set_state(ADEFSTATE_DISABLED);
	}

	/*
	 * First verify that the columns if specified do not conflict with the alert columns
	 */
	for (uint32_t i = 0; i < ncols_; ++i) {
		if (auto pcol = get_jsoncrc_mapping(pconstcolarr_[i]->jsonfield, pconstcolarr_[i]->szjson, json_db_alerts_arr, GY_ARRAY_SIZE(json_db_alerts_arr)); pcol) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alert name \'%s\' : Column name used \'%s\' conflicts with Alert field. "
						"Please use a different column name", pname, pconstcolarr_[i]->jsonfield);
		}	
	}

	const auto		& obj = jdoc.GetObject();

	auto 			it = obj.FindMember("severity"); 
	
	if (it != obj.MemberEnd()) {
		severity_ = ALERT_SEVERITY(it->value, asubsys_, pasubsys_, pconstcolarr_, ncols_, is_multi_host_);
	}	

	it = obj.FindMember("annotations"); 
	
	if (it != obj.MemberEnd()) {
		annotations_ = ALERT_ANNOTATIONS(it->value, pconstcolarr_, ncols_);
	}	

	it = obj.FindMember("action"); 

	if (it == obj.MemberEnd()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alert name \'%s\' : Required field \'action\' missing", pname);
	}	
	else if (false == it->value.IsArray()) {
		if (it->value.IsString()) {

			action_.reserve(1);

			auto			fit = palertmgr->actionmap_.find(get_adef_id(it->value.GetString(), it->value.GetStringLength()));

			if (fit == palertmgr->actionmap_.end()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alert name \'%s\' : \'action\' name referenced \'%s\' not found", pname, it->value.GetString());
			}	
				
			action_.emplace_back(new ADEF_ACTION(fit->second, nullptr, asubsys_, pasubsys_, pconstcolarr_, ncols_, is_multi_host_, true));
		}
		else {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alert name \'%s\' : Field \'action\' not of JSON Array type", pname);
		}
	}	
	else {
		if (0 == it->value.Size()) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alert name \'%s\' : Field \'action\' Array is empty", pname);
		}
		else if (it->value.Size() > MAX_DEF_ACTIONS) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alert name \'%s\' : Field \'action\' Array size %u greater than max Actions per definition %lu", 
									pname, it->value.Size(), MAX_DEF_ACTIONS);
		}	
		
		action_.reserve(it->value.Size());

		for (uint32_t i = 0; i < it->value.Size(); i++) {
			if (false == it->value[i].IsObject()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alert name \'%s\' : \'action\' Array element %u not of JSON Object type", pname, i + 1);
			}	

			const auto 		& oa = it->value[i].GetObject();

			auto 			ait = oa.FindMember("name");

			if (ait == oa.MemberEnd()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alert name \'%s\' : \'action\' object does not contain required field \'name\' of an existing Action", 
						pname);
			}
			else if (!ait->value.IsString()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alert name \'%s\' : \'action\' object field \'name\' not of String type", pname);
			}	

			auto			fit = palertmgr->actionmap_.find(get_adef_id(ait->value.GetString(), ait->value.GetStringLength()));

			if (fit == palertmgr->actionmap_.end()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alert name \'%s\' : \'action\' name referenced \'%s\' not found", pname, ait->value.GetString());
			}	
			
			action_.emplace_back(new ADEF_ACTION(fit->second, std::addressof(it->value[i]), asubsys_, pasubsys_, pconstcolarr_, ncols_, is_multi_host_, i + 1 == it->value.Size()));
		}
	}	
	
	it = obj.FindMember("mutetimes"); 

	if (it != obj.MemberEnd()) {
		if (false == it->value.IsArray()) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alert name \'%s\' : Field \'mutetimes\' not of JSON Array type", pname);
		}	
		else if (it->value.Size()) {
			pmute_ = std::make_unique<MUTE_TIMES>(it->value);

			if (is_enabled()) {
				struct tm			tmstart = {};

				localtime_r(&tcurr, &tmstart);
				
				if (true == pmute_->in_range(tmstart, tcurr)) {
					set_state(ADEFSTATE_MUTED);
				}	
			}
		}	
	}	
	
	it = obj.FindMember("labels"); 

	if (it != obj.MemberEnd()) {
		if (false == it->value.IsArray()) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alert name \'%s\' : Field \'labels\' not of JSON Array type", pname);
		}	

		uint32_t			lsz = 0;

		for (uint32_t i = 0; i < it->value.Size(); i++) {
			if (false == it->value[i].IsString()) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alert name \'%s\' : \'labels\' Array element %u not of JSON String type", pname, i + 1);
			}	
			
			lsz += it->value[i].GetStringLength();
		}	

		if (lsz > 0) {
			labels_.reserve(lsz + it->value.Size() * 2);

			for (uint32_t i = 0; i < it->value.Size(); i++) {
				if (memchr(it->value[i].GetString(), ',', it->value[i].GetStringLength())) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alert name \'%s\' : \'labels\' element \'%s\' contains character \',\' which is not allowed", 
						pname, it->value[i].GetString());
				}

				labels_.append(it->value[i].GetString(), it->value[i].GetStringLength());

				if (i + 1 < it->value.Size()) {
					labels_ += ", ";
				}	
			}
		}
	}	

	it = obj.FindMember("groupby"); 

	if (it != obj.MemberEnd()) {
		if (false == it->value.IsArray()) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definition for alert name \'%s\' : Field \'groupby\' not of JSON Array type", pname);
		}	
		else {
			groupby_ = ALERT_GROUPBY(it->value, asubsys_, pasubsys_, pconstcolarr_, ncols_);
		}	
	}	
}	

AActionVec ALERTDEF::get_actions(const AlertStatFilter & filter, STR_WR_BUF & actstrbuf) const
{
	AActionVec			vec;

	for (const auto & pactdef : action_) {
		if (!pactdef || !pactdef->actionshr_ || pactdef->actionshr_->is_deleted()) {
			continue;
		}

		if (CRIT_FAIL != filter.filter_match(pactdef->match_)) {

			vec.emplace_back(pactdef);
			actstrbuf << pactdef->actionshr_->name_.get_view() << ", ";

			if (pactdef->continue_ == false) {
				break;
			}	
		}	
	}	

	if (vec.size()) {
		actstrbuf -= GY_CONST_STRLEN(", "); 
	}

	return vec;
}

void ALERTDEF::check_actions() noexcept
{
	try {
		int			nupd = 0;

		for (const auto & pactdef : action_) {
			if (!pactdef || !pactdef->actionshr_) {
				continue;
			}

			if (pactdef->actionshr_->is_deleted()) {
				const char		*pname = pactdef->actionshr_->name();
				auto			fit = galertmgr->actionmap_.find(get_adef_id(pname, strlen(pname)));

				if (fit != galertmgr->actionmap_.end()) {
					const auto		& pact = fit->second;

					if (bool(pact) && !pact->is_deleted()) {
						pactdef->actionshr_ = pact;
						nupd++;
					}	
				}	
			}	
		}	

		DEBUGEXECN(1,
			if (nupd > 0) {
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Updated %d Deleted Actions with new ones for Alert Definition %s\n", nupd, name());
			}
		);	
	}
	GY_CATCH_EXPRESSION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking definition actions : %s\n", GY_GET_EXCEPT_STRING);
		);
	);
}	

// Called under SHCONN_HANDLER Accept thread context (sock is non-blocking)
void ALERTMGR::add_node_action_sock(int sock, uint8_t *pregbuf, uint32_t lenbuf) noexcept
{
	try {
		if (sock < 0) {
			return;
		}	

		SCOPE_FD			sfd(sock);

		if (!pregbuf || lenbuf != sizeof(COMM_HEADER) + sizeof(NS_REGISTER_REQ_S)) {
			return;
		}	

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(pregbuf);
		NS_REGISTER_REQ_S		*preg = reinterpret_cast<NS_REGISTER_REQ_S *>(phdr + 1);
		char				ebuf[COMM_MAX_ERROR_LEN];
		ERR_CODES_E			errcode;

		if (false == phdr->validate()) {
			return;
		}

		if (false == preg->validate(phdr)) {
			return;
		}	

		if (false == preg->validate_fields(gmin_node_version, gversion_num, ebuf, errcode)) {
			gshconnhdlr->sock_register_connect_error<NS_REGISTER_RESP_S, NS_REGISTER_RESP>(sock, errcode, ebuf, COMM_HEADER::NS_HDR_MAGIC);

			ERRORPRINT_OFFLOAD("Node Action Registration for %s Failed due to %s\n", preg->node_hostname_, ebuf);
			return;
		}	

		ACT_MSG				actmsg(std::move(sfd), pregbuf, lenbuf);
		int				ntries = 0;
		bool				bret;

		do { 
			bret = acthdlr_.aqueue_.write(std::move(actmsg));
		} while (bret == false && ntries++ < 2);

		if (bret == false) {
			acthdlr_.npoolblocks_++;

			const char		*pstr = "Alertmgr Action Handler is blocked handling prior actions";

			gshconnhdlr->sock_register_connect_error<NS_REGISTER_RESP_S, NS_REGISTER_RESP>(sock, ERR_BLOCKING_ERROR, pstr, COMM_HEADER::NS_HDR_MAGIC);

			ERRORPRINT_OFFLOAD("Node Action Registration for %s Failed due to : %s\n", preg->node_hostname_, pstr);
			return;
		}
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT_OFFLOAD("Exception caught while handling Node Action Registration : %s\n", GY_GET_EXCEPT_STRING);
	);
}	


void NODE_ACTION_SOCK::close_conn(bool graceful_close) noexcept
{
	int			sock = get_sock();

	if (sock >= 0) {
		if (graceful_close) {
			gy_close_socket(sock);
		}
		else {
			(void)::close(sock);
		}	
	}
	else {
		return;
	}	

	time_t			tcurr 	= time(nullptr);

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Closed Node Alert Action Socket %s : Alert Actions Sent %lu : Connected %ld sec earlier\n", 
						desc_.get(), nact_sent_, tcurr - tstart_);

	reset();
}	


void ACTION_HDLR::node_register(ACT_MSG && amsg, time_t tcurr) noexcept
{
	try {
		if (!amsg.conf_json_ || amsg.lenconf_ != sizeof(COMM_HEADER) + sizeof(NS_REGISTER_REQ_S) || amsg.sockfd_.get() < 0) {
			DEBUGEXECN(1,
				WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alertmgr Node Register called with invalid Msg Params : Skipping\n");
			);
			return;
		}	
		
		COMM_HEADER			*hdr = reinterpret_cast<COMM_HEADER *>(amsg.conf_json_.get());
		NS_REGISTER_REQ_S		*preg = reinterpret_cast<NS_REGISTER_REQ_S *>(hdr + 1);
		int				sock = amsg.sockfd_.get();

		NODE_ACTION_SOCK		*pnode = nullptr;
		uint32_t			lenhost = strlen(preg->node_hostname_), ntotsocks = 0, nsocks = 0;
		uint32_t			nodeid = get_adef_id(preg->node_hostname_, lenhost);

		for (uint32_t i = 0; i < GY_ARRAY_SIZE(nodearr_); ++i) {
			auto			& node = nodearr_[i];

			if (node.is_valid()) {
				ntotsocks++;

				if (node.nodeid_ == nodeid) {
					nsocks++;
				}	
			}	
		}

		if (ntotsocks == GY_ARRAY_SIZE(nodearr_)) {
			const char 		*perr = "Max Node Action Socket Count already reached";

			gshconnhdlr->sock_register_connect_error<NS_REGISTER_RESP_S, NS_REGISTER_RESP>(sock, ERR_BLOCKING_ERROR, 
					perr, COMM_HEADER::NS_HDR_MAGIC);

			ERRORPRINT_OFFLOAD("Node Action Registration for %s Failed due to %s\n", preg->node_hostname_, perr);
			return;
		}	

		if (nsocks >= MAX_SOCKS_PER_NODE) {
			const char 		*perr = "Max Per Node Action Socket Count already reached";

			gshconnhdlr->sock_register_connect_error<NS_REGISTER_RESP_S, NS_REGISTER_RESP>(sock, ERR_BLOCKING_ERROR, 
					perr, COMM_HEADER::NS_HDR_MAGIC);

			ERRORPRINT_OFFLOAD("Node Action Registration for %s Failed due to %s\n", preg->node_hostname_, perr);
			return;
		}	

		for (uint32_t i = 0; i < GY_ARRAY_SIZE(nodearr_); ++i) {
			auto			& node = nodearr_[i];

			if (!node.is_valid()) {
				node = NODE_ACTION_SOCK(sock, nodeid, preg->node_hostname_, lenhost, tcurr);
				pnode = &node;
				break;
			}	
		}
		
		if (!pnode) {
			return;
		}	

		last_node_version_		= preg->node_version_;

		// Set the socket to Blocking mode and send the Register Response

		set_sock_nonblocking(sock, 0 /* to_set */);

		static constexpr size_t		fixed_sz = sizeof(comm::COMM_HEADER) + sizeof(NS_REGISTER_RESP_S);
		
		alignas(8) char			palloc[fixed_sz];

		comm::COMM_HEADER		*phdr = reinterpret_cast<comm::COMM_HEADER *>(palloc);
		NS_REGISTER_RESP_S		*presp = reinterpret_cast<NS_REGISTER_RESP_S *>(phdr + 1); 
		
		new (phdr) comm::COMM_HEADER(NS_REGISTER_RESP, fixed_sz, COMM_HEADER::NS_HDR_MAGIC);

		std::memset((void *)presp, 0, sizeof(*presp));

		presp->error_code_		= ERR_SUCCESS;
		GY_STRNCPY(presp->error_string_, "Successfully Registered", sizeof(presp->error_string_));

		presp->shyama_version_		= gversion_num;

		snprintf(presp->shyama_id_, sizeof(presp->shyama_id_), "%016lx", gshconnhdlr->gshyama_id_);

		struct iovec			iov[3] {{phdr, sizeof(*phdr)}, {presp, sizeof(*presp)}, {(void *)gshconnhdlr->gpadbuf, phdr->get_pad_len()}};	
		ssize_t				sret;
		
		sret = gy_writev(sock, iov, GY_ARRAY_SIZE(iov));
		
		if (sret == phdr->get_total_len()) {
			amsg.sockfd_.release();

			count_conns();

			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Registered new Node Action Socket from \'%s\' : Total connections active %u\n", 
								preg->node_hostname_, ntotalconns_);
		}
		else {
			PERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "New Node Action Register from \'%s\' failed as sending response failed", preg->node_hostname_);

			// sockfd_ will be closed by amsg destructor
			pnode->reset();
		}	
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while registering new Node Action Connection : %s\n", GY_GET_EXCEPT_STRING);
	);
}

void ACTION_HDLR::print_stats(int64_t tsec, time_t tcurr) noexcept
{
	using Nodemap 			= INLINE_STACK_HASH_MAP<uint32_t, const char *, 2048, GY_JHASHER<uint32_t>>;
	
	STRING_BUFFER<4096>		strbuf;

	strbuf << "Alertmgr Action Handler Stats for the last " << tsec << " secs : \n\t\t\t" 
		<< nsent_ - lastnsent_ << " Alerts sent, " << nfailed_ - lastnfailed_ << " Failed Alerts (by socket failures or internal errors), " 
		<< nnoconns_ - lastnnoconns_ << " Alerts Skipped by no Node Connections, " 
		<< GY_READ_ONCE(npoolblocks_) - lastnpoolblocks_ << " Alerts missed by Pool Blocks, "
		<< GY_READ_ONCE(nstrbufovf_) - lastnstrbufovf_ << " Alerts missed by Buffer overflows" 
		
		<< "\n\t\t\tCumulative Stats : " 
		<< nsent_ << " Alerts sent, " << nfailed_ << " Failed Alerts, " << nnoconns_  << " Alerts Skipped by no Node Connections, "
		<< GY_READ_ONCE(npoolblocks_) << " Alerts missed by Pool Blocks, "
		<< GY_READ_ONCE(nstrbufovf_) << " Alerts missed by Buffer overflows"; 

	lastnsent_ 		= nsent_;
	lastnfailed_		= nfailed_;
	lastnnoconns_		= nnoconns_;
	lastnpoolblocks_	= npoolblocks_;
	lastnstrbufovf_		= nstrbufovf_;

	strbuf 	<< "\n\t\t\tTotal Node Action Connections are " << ntotalconns_;
	
	if (tcurr > tdescprint_ and ntotalconns_ > 0) {
		try {
			Nodemap				nodemap;

			for (uint32_t i = 0; i < GY_ARRAY_SIZE(nodearr_); ++i) {
				if (nodearr_[i].sock_ < 0) continue;

				nodemap.try_emplace(nodearr_[i].nodeid_, nodearr_[i].desc_.get());
			}	

			ntotalprocs_ = nodemap.size();

			strbuf << " from these " << ntotalprocs_ << " Nodes : \n\t\t\t";
			
			for (const auto [id, desc] : nodemap) {
				strbuf << desc << ", ";
			}	

		}
		catch(...) {
		}	

		tdescprint_ = time(nullptr) + 300;
	}

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "%s\n\n", strbuf.buffer());
}

/*
 * NOTE : Currently we do not parse the Node Action incoming data sent and directly ignore all data
 * Change this if Alert Action Status to be sent by Node and parsed...
 */
void ACTION_HDLR::check_node_recv(time_t tcurr) noexcept
{
	GY_SCOPE_EXIT {
		count_conns();
	};

	try {
		alignas(8) char		rbuf[16 * 1024];
		ssize_t			sret;
		struct pollfd		pfds[MAX_NODE_CONNS];
		int			ret, nclose = 0;

try_again :
		for (uint32_t i = 0; i < MAX_NODE_CONNS; ++i) {
			pfds[i].fd	= nodearr_[i].sock_;
			pfds[i].events	= POLLIN;
			pfds[i].revents	= 0;
		}	

		ret = ::poll(pfds, MAX_NODE_CONNS, 0);

		if (ret <= 0) {
			return;
		}	
		else if (errno == EINTR) {
			goto try_again;
		}
			
		for (uint32_t i = 0; i < MAX_NODE_CONNS; ++i) {
			if (pfds[i].revents == 0) {
				continue;
			}	
			else if (pfds[i].revents & (POLLHUP | POLLERR)) {
				nodearr_[i].close_conn();
				nclose++;
			}
			else if (pfds[i].revents & POLLNVAL) {
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Node Alert Action socket reported as already closed during socket check. This indicates an internal error...\n");

				nodearr_[i].reset();
				nclose++;
			}	
			else if (pfds[i].revents & POLLIN) {
				
				// We limit to 64 KB per iteration per socket
				for (int n = 0; n < 4; ++n) {
					sret = ::recv(nodearr_[i].sock_, rbuf, sizeof(rbuf), MSG_DONTWAIT);

					if (sret < 0) {
						if (errno == EINTR) {
							continue;
						}	

						// Handle any socket errors during the next poll
						break;
					}	
					else if (sret > 0) {
						nodearr_[i].tlast_recv_ = tcurr;

						if ((size_t)sret < sizeof(rbuf)) {
							break;
						}	
					}	
					else {
						nodearr_[i].close_conn();
						nclose++;
					}	
				}
			}
		}
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking Node Action Connections : %s\n", GY_GET_EXCEPT_STRING);
	);
}	

NODE_ACTION_SOCK * ACTION_HDLR::get_action_conn(time_t tcurr, int16_t events, int timeoutmsec)
{
	struct pollfd		pfds[MAX_NODE_CONNS];
	int			ret, nclose, nsocks, nretries = 0;

try_again :
	nclose = 0;
	nsocks = 0;

	for (uint32_t i = 0; i < MAX_NODE_CONNS; ++i) {
		pfds[i].fd	= nodearr_[i].sock_;
		pfds[i].events	= events;
		pfds[i].revents	= 0;

		nsocks 		+= (nodearr_[i].sock_ >= 0);
	}
	
	if (nsocks == 0) {
		return nullptr;
	}	
	
	ret = ::poll(pfds, MAX_NODE_CONNS, timeoutmsec);

	if (ret <= 0) {
		return nullptr;
	}	
	else if (errno == EINTR) {
		goto try_again;
	}
		
	for (uint32_t i = 0; i < MAX_NODE_CONNS; ++i) {
		if (pfds[i].revents == 0) {
			continue;
		}	
		else if (pfds[i].revents & (POLLHUP | POLLERR)) {
			nodearr_[i].close_conn();
			nclose++;
		}
		else if (pfds[i].revents & POLLNVAL) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Node Alert Action socket reported as already closed during socket check. This indicates an internal error...\n");

			nodearr_[i].reset();
			nclose++;
		}	
		else if (pfds[i].revents & POLLOUT) {
			return nodearr_ + i;
		}
	}

	if (nclose > 0) {
		if ((0 == count_conns()) || (++nretries == 2) || (timeoutmsec == 0)) {
			return nullptr;
		}	
		
		time_t			tnew = time(nullptr);

		if (tnew > tcurr + uint32_t(timeoutmsec)/1000) {
			return nullptr;
		}	

		if (timeoutmsec > 0) {
			timeoutmsec -= (tnew - tcurr) * 1000;

			if (timeoutmsec < 0) {
				timeoutmsec = 0;
			}	
		}

		goto try_again;
	}	

	return nullptr;
}

void ACTION_HDLR::send_alert(ACT_MSG && amsg, time_t tcurr) noexcept
{
	try {
		if (!amsg.conf_json_ || !amsg.lenconf_ || !amsg.nalerts_ || amsg.nalerts_ > MAX_ONE_ACTION_ALERTS) {
			return;
		}

		auto				*pconn = get_action_conn(tcurr, POLLOUT, 5000);
		
		if (!pconn) {
			nnoconns_++;
			return;
		}	

		int				niov = 0;
		ssize_t				sret;
		struct iovec			iovarr[64];
		alignas(8) char			commbuf[sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY)];			
		
		iovarr[niov++] = {
			.iov_base		= commbuf,
			.iov_len		= sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY),
		};	

		iovarr[niov++] = {
			.iov_base		= amsg.conf_json_.get(),
			.iov_len		= amsg.lenconf_,
		};	

		for (uint32_t i = 0; i < amsg.nalerts_; ++i) {

			if (!amsg.alertstrarr_[i] || !amsg.lenalertstr_[i]) {
				nfailed_++;
				return;
			}	

			if ((uint32_t)niov + 4 > GY_ARRAY_SIZE(iovarr)) {
				nfailed_++;
				return;
			}	
			
			iovarr[niov++] = {
				.iov_base		= amsg.alertstrarr_[i].get(),
				.iov_len		= amsg.lenalertstr_[i],
			};	
			
			if (bool(amsg.alertdataarr_[i]) && amsg.alertdataarr_[i]->size()) {

				iovarr[niov++] = {
					.iov_base	= amsg.alertdataarr_[i]->data(),
					.iov_len	= amsg.alertdataarr_[i]->size(),
				};	
			}	

			const char			*tstr = "},";

			iovarr[niov++] = {
				.iov_base		= (void *)tstr,
				.iov_len		= (i + 1 < amsg.nalerts_ ? 2u : 1u),
			};	
		}	

		if ((uint32_t)niov + 3 > GY_ARRAY_SIZE(iovarr)) {
			nfailed_++;
			return;
		}	

		iovarr[niov++] = {
			.iov_base		= (void *)"],\"weburl\":",
			.iov_len		= GY_CONST_STRLEN("],\"weburl\":"),
		};	

		iovarr[niov++] = {
			.iov_base		= (void *)gsettings->esc_webserver_url.data(),
			.iov_len		= gsettings->esc_webserver_url.size(),
		};	

		iovarr[niov++] = {
			.iov_base		= (void *)"}",
			.iov_len		= 1,
		};	

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(commbuf);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 

		size_t				tbytes = iovec_bytes(iovarr, niov);

		new (phdr) comm::COMM_HEADER(COMM_EVENT_NOTIFY, tbytes, COMM_HEADER::NS_HDR_MAGIC);

		new (pnot) EVENT_NOTIFY(NOTIFY_JSON_EVENT, 1);

		assert(phdr->get_total_len() == tbytes);

		// Blocking write
		sret = gy_writev(pconn->sock_, iovarr, niov);
		
		if (sret == phdr->get_total_len()) {
			nsent_++;

			pconn->tlast_ = tcurr;
			pconn->nact_sent_++;
		}
		else {
			nfailed_++;
		}	
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while sending Node Action Alert : %s\n", GY_GET_EXCEPT_STRING);
	);
}	

int ALERTMGR::alert_act_thread() noexcept
{
	time_t			tcurr = time(nullptr), tnext, tnoderecv = tcurr + 30, tprint = tcurr + 60, tlastprint = tcurr;

	act_thr_.set_thread_init_done();

	do {
		try {
			ACT_MSG			amsg;
			bool			bret;

			tcurr = time(nullptr);
			tnext = tcurr + 5;

			bret = acthdlr_.aqueue_.tryReadUntil(std::chrono::system_clock::from_time_t(tnext), amsg);
			
			tcurr = time(nullptr);
				
			if (bret) {
				
				switch (amsg.atype_) {

				case ACT_MSG::ANewAlert :
				case ACT_MSG::ACloseAlert :	
					
					acthdlr_.send_alert(std::move(amsg), tcurr);
					tcurr = time(nullptr);
					break;

				case ACT_MSG::ANodeRegister :

					acthdlr_.node_register(std::move(amsg), tcurr);
					tcurr = time(nullptr);
					break;

				default :
					break;
				}
			}	

			if (tcurr > tprint) {
				acthdlr_.print_stats(tcurr - tlastprint, tcurr);

				tprint 		= tcurr + 300;
				tlastprint 	= tcurr;
			}	

			if (tcurr > tnoderecv) {
				acthdlr_.check_node_recv(tcurr);

				tcurr = time(nullptr);
				tnoderecv = tcurr + 30;
			}	
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught in Alertmgr Action thread : %s\n\n", GY_GET_EXCEPT_STRING);
		);
	} while (true);
	
	return -1;

}	


bool ALERT_DB_HDLR::db_new_alert_stat(ADB_MSG & amsg) noexcept
{
	try {
		if (amsg.mtype_ != ADB_MSG::MsgNew) {
			return false;
		}	
		
		auto				pconn = dbpool_.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
		
		if (!pconn) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to insert new Alert to DB\n");

			gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
			gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

			return false;
		}	

		static_assert(
		json_db_alerts_arr[0].jsoncrc 	== FIELD_ALERTTIME 	&& json_db_alerts_arr[1].jsoncrc 	== FIELD_ALERTID 	&& 
		json_db_alerts_arr[2].jsoncrc 	== FIELD_ALERTNAME 	&& json_db_alerts_arr[3].jsoncrc 	== FIELD_ASTATE 	&& 
		json_db_alerts_arr[4].jsoncrc 	== FIELD_SEVERITY 	&& json_db_alerts_arr[5].jsoncrc 	== FIELD_EXPIRY 	&& 
		json_db_alerts_arr[6].jsoncrc 	== FIELD_TACTION 	&& json_db_alerts_arr[7].jsoncrc 	== FIELD_TCLOSE 	&& 
		json_db_alerts_arr[8].jsoncrc 	== FIELD_ADEFID		&& json_db_alerts_arr[9].jsoncrc 	== FIELD_ACTIONS 	&& 
		json_db_alerts_arr[10].jsoncrc 	== FIELD_ANNOT 		&& json_db_alerts_arr[11].jsoncrc 	== FIELD_ACKNOTES 	&& 
		json_db_alerts_arr[12].jsoncrc 	== FIELD_NREPEATS 	&& json_db_alerts_arr[13].jsoncrc 	== FIELD_SUBSYS 	&& 
		json_db_alerts_arr[14].jsoncrc 	== FIELD_LABELS 	&& json_db_alerts_arr[15].jsoncrc 	== FIELD_ALERTDATA, 	
		"Please update the columns in the insert sql below");
	
		STRING_BUFFER<1024>		qbuf;
		auto				datetbl = get_db_day_partition(amsg.talert_);
		bool				bret;

		nnew_++;

		qbuf << "insert into public.alertstbl" << datetbl.get() << " values ($1::timestamptz, $2::char(8), $3::text, $4::text, $5::char(8), "
				"$6::timestamptz, $7::timestamptz, $8::timestamptz, $9::char(8), $10::text, $11::text, $12::text, "
				"$13::smallint, $14::text, $15::text, $16::text)\n;";

		bret = PQsendQueryParams(pconn->get(), qbuf.get(), GY_ARRAY_SIZE(json_db_alerts_arr), nullptr, amsg.parambufs_, nullptr, nullptr, 0);

		if (bret == false) {
			gshconnhdlr->db_stats_.nalerts_failed_.fetch_add_relaxed(1);

			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to update DB with New Alert due to %s\n", PQerrorMessage(pconn->get()));
			return false;
		}	

		pconn->set_resp_cb(
			[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
			{
				if (is_completed) {
					if (conn.is_within_tran()) {
						conn.pqexec_blocking("Rollback Work;");
					}						
					conn.make_available();
					return true;
				}	
				
				if (true == gyres.is_error()) {
					gshconnhdlr->db_stats_.nalerts_failed_.fetch_add_relaxed(1);

					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to update DB with New Alert due to %s\n", gyres.get_error_msg());
					return false;
				}	

				return true;
			}
		);

		
		return true;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while writing to Alertmgr DB new Alerts : %s\n", GY_GET_EXCEPT_STRING);
		);

		return false;
	);
}	

bool ALERT_DB_HDLR::db_upd_alert_stat(ADB_MSG & amsg) noexcept
{
	try {
		auto				pconn = dbpool_.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
		
		if (!pconn) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to update Alert Status to DB\n");

			gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
			gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

			return false;
		}	

		STRING_BUFFER<1024>		qbuf;
		auto				datetbl = get_db_day_partition(amsg.talert_);
		const char			*params[2] {};
		uint32_t			nparams = 0;
		bool				bret;

		qbuf << "update public.alertstbl" << datetbl.get() << ' ';

		switch (amsg.mtype_) {
		
		case ADB_MSG::MsgResolved :
			nresolved_++;

			qbuf << "set astate = \'resolved\', tclose = to_timestamp(" << amsg.tupdate_ << ") ";
			break;
		
		case ADB_MSG::MsgExpired :
			nexpired_++;

			qbuf << "set astate = \'expired\', tclose = to_timestamp(" << amsg.tupdate_ << ") ";
			break;

		case ADB_MSG::MsgAck :
			nack_++;

			qbuf << "set astate = \'acked\' ";
			if (amsg.alertstr_.size()) {
				qbuf << ", acknotes = $1::text ";
				params[0] 	= amsg.alertstr_.data();
				nparams		= 1;
			}	
			
			break;

		default :
			return false;
		}	

		static_assert(json_db_alerts_arr[0].jsoncrc == FIELD_ALERTTIME && json_db_alerts_arr[1].jsoncrc == FIELD_ALERTID);

		qbuf.appendfmt(" where %s = to_timestamp(%ld) and %s = \'%08x\';\n", json_db_alerts_arr[0].dbcolname, amsg.talert_, json_db_alerts_arr[1].dbcolname, amsg.alertid_);

		bret = PQsendQueryParams(pconn->get(), qbuf.get(), nparams, nullptr, params, nullptr, nullptr, 0);

		if (bret == false) {
			gshconnhdlr->db_stats_.nalerts_failed_.fetch_add_relaxed(1);

			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to update DB with Alert Status update due to %s\n", PQerrorMessage(pconn->get()));
			return false;
		}	

		pconn->set_resp_cb(
			[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
			{
				if (is_completed) {
					if (conn.is_within_tran()) {
						conn.pqexec_blocking("Rollback Work;");
					}						
					conn.make_available();
					return true;
				}	
				
				if (true == gyres.is_error()) {
					gshconnhdlr->db_stats_.nalerts_failed_.fetch_add_relaxed(1);

					ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to update DB with Alert Status update due to %s\n", gyres.get_error_msg());
					return false;
				}	

				return true;
			}
		);

		
		return true;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while writing to Alertmgr DB Alert Status update : %s\n", GY_GET_EXCEPT_STRING);
		);

		return false;
	);
}


void ALERT_DB_HDLR::print_stats(int64_t tsec) noexcept
{
	STRING_BUFFER<1024>		strbuf;

	strbuf << "Alertmgr DB Stats for the last " << tsec << " secs : " 
		<< nnew_ - lastnnew_ << " New Alerts, " << nresolved_ - lastnresolved_ << " Resolved, " << nexpired_ - lastnexpired_ << " Expired, " 
		<< nack_ - lastnack_ << " Acked, " << GY_READ_ONCE(npoolblocks_) - lastnpoolblocks_ << " DB Alerts missed by Pool Blocks, "
		<< GY_READ_ONCE(nstrbufovf_) - lastnstrbufovf_ << " DB Alerts missed by Buffer overflows\n" 
		
		<< "\t\t\tCumulative DB Stats : " 
		<< nnew_ << " Alerts, " << nresolved_ << " Resolved, " << nexpired_  << " Expired, "
		<< nack_ << " Acked, " << GY_READ_ONCE(npoolblocks_) << " DB Alerts missed by Pool Blocks, "
		<< GY_READ_ONCE(nstrbufovf_) << " DB Alerts missed by Buffer overflows"; 

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "%s\n\n", strbuf.buffer());

	lastnnew_ 		= nnew_;
	lastnresolved_		= nresolved_;
	lastnexpired_		= nexpired_;
	lastnack_		= nack_;
	lastnpoolblocks_	= npoolblocks_;
	lastnstrbufovf_		= nstrbufovf_;
}	

int ALERTMGR::alert_db_thread() noexcept
{
	time_t			tcurr = time(nullptr), tnext, tpoolreset = tcurr + 300, tprint = tcurr + 60, tlastprint = tcurr;

	db_thr_.set_thread_init_done();

	do {
		try {
			ADB_MSG			amsg;
			bool			bret;

			tcurr = time(nullptr);
			tnext = tcurr + 60;

			bret = dbhdlr_.aqueue_.tryReadUntil(std::chrono::system_clock::from_time_t(tnext), amsg);
			
			if (bret) {
				
				switch (amsg.mtype_) {

				case ADB_MSG::MsgNew :
					dbhdlr_.db_new_alert_stat(amsg);
					break;

				case ADB_MSG::MsgResolved :
				case ADB_MSG::MsgExpired :
				case ADB_MSG::MsgAck :

					dbhdlr_.db_upd_alert_stat(amsg);
					break;

				default :
					break;
				}
			}	

			tcurr = time(nullptr);

			if (tcurr > tprint) {
				dbhdlr_.print_stats(tcurr - tlastprint);

				tprint 		= tcurr + 300;
				tlastprint 	= tcurr;
			}	

			if (tcurr > tpoolreset) {
				dbhdlr_.dbpool_.reset_idle_conns();

				tcurr = time(nullptr);
				tpoolreset = tcurr + 300;
			}	

		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught in Alertmgr DB thread : %s\n\n", GY_GET_EXCEPT_STRING);
		);
	} while (true);
	
	return -1;
}	

void ALERTMGR::set_cfg_inhibits(const char *pfilename, const char *pcfg, size_t lencfg)
{
	JSON_DOCUMENT<32 * 1024, 8192>	doc;
	auto				& jdoc = doc.get_doc();
	JSON_ALLOCATOR			& allocator = jdoc.GetAllocator();

	jdoc.Parse(pcfg, lencfg);

	if (jdoc.HasParseError()) {
		char			ebuf[256];
		const char		*perrorstr = rapidjson::GetParseError_En(jdoc.GetParseError());

		ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid Alert Inhibits Config CFG_INHIBITS_JSON : Error at offset %lu : Error is \'%s\'\n\n", 
			jdoc.GetErrorOffset(), perrorstr);

		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid JSON for Alert Inhibits Config CFG_INHIBITS_JSON file %s", pfilename);
	}	

	if (false == jdoc.IsArray()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Inhibits Config CFG_INHIBITS_JSON file %s : Needs to be a JSON Array type", pfilename);
	}	

	time_t				tcurr = time(nullptr);
	STRING_BUFFER<1024>		strbuf;
	int				nadded = 0;
	bool				bret;

	// First truncate existing inhibits...
	if (true) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Alert Inhibits Config CFG_INHIBITS_JSON file %s seen : Deleting existing DB Inhibits first...\n", pfilename);

		auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
		
		if (!pconn) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to Postgres for Alert Inhibits truncation\n");

			gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
			gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);
		}
		else {
			pconn->pqexec_blocking("truncate table public.inhibitstbl;");
		}
	}	
	
	for (uint32_t i = 0; i < jdoc.Size(); i++) {

		STACK_JSON_WRITER<8096, 4096>	objwriter;
		const char			*pjson;
		uint32_t			szjson;

		jdoc[i].Accept(objwriter); 

		pjson 		= objwriter.get_string();
		szjson		= objwriter.get_size();

		strbuf.reset();

		auto 				[errcode, inhid, pname] = add_inhibit(0, jdoc[i], strbuf, tcurr, tcurr);

		if (inhid != 0) {
			nadded++;

			DEBUGEXECN(1,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Alertmgr : Added Alert Inhibit from Inhibit Config file : \'%s\'\n", pname);
			);
		}	
		else {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Failed to add new Alert Inhibit from Config file : %s", strbuf.buffer()); 
		}

		db_insert_inhibit(inhid, pname, tcurr, pjson, szjson);
	}
		
	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Added %u Alert Inhibits from Inhibits Config file %s\n", nadded, pfilename);
}

void ALERTMGR::read_db_inhibits()
{
	auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Alert Inhibits info from db\n");

		gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return;
	}	

	int				ret, nadded = 0;
	bool				bret;
	time_t				tcurr = time(nullptr);

	const JSON_DB_MAPPING		*colarr[GY_ARRAY_SIZE(json_db_inhibits_arr)] {};
	size_t				ncol;
	STRING_BUFFER<1024>		strbuf;

	strbuf << "select inhid, tcreated, disabled, inhibit from public.inhibitstbl limit " << ALERT_INHIBIT::MAX_INHIBITS << "\n;";

	bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.length());

	if (bret == false) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule query Postgres for Alert Inhibits info from db\n");

		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return;
	}	

	ncol 				= 4;

	colarr[0]			= &json_db_inhibits_arr[0];
	colarr[1]		 	= &json_db_inhibits_arr[2];
	colarr[2]			= &json_db_inhibits_arr[3];
	colarr[3]			= &json_db_inhibits_arr[4];

	static_assert(json_db_inhibits_arr[0].jsoncrc == FIELD_INHID);
	static_assert(json_db_inhibits_arr[2].jsoncrc == FIELD_TCREATED);
	static_assert(json_db_inhibits_arr[3].jsoncrc == FIELD_DISABLED);
	static_assert(json_db_inhibits_arr[4].jsoncrc == FIELD_INHIBIT);

	const auto rowcb = [&](int numrow, const JSON_DB_MAPPING **pcolarr, std::string_view colview[], uint32_t ncol)
	{
		JSON_DOCUMENT<2048, 2048>	doc;
		auto				& jdoc = doc.get_doc();
		uint32_t			inhid;
		time_t				tcreate;
		bool				is_disabled;
		
		if (colview[0].size() == 0) {
			return;
		}	

		inhid = string_to_number<uint32_t>(colview[0].data(), 16);
		if (inhid == 0) {
			return;
		}	

		if (colview[1].size() > 0) {
			tcreate = gy_iso8601_to_time_t(CHAR_BUF<64>(colview[1].data(), colview[1].size()).get());
		}
		else {
			tcreate = tcurr;
		}

		if (colview[2].size() > 0) {
			is_disabled = (*(colview[2].data()) == 't');
		}	
		else {
			is_disabled = false;
		}	

		if (colview[3].size() == 0) {
			return;
		}	
		if (jdoc.Parse(colview[3].data(), colview[3].size()).HasParseError()) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Invalid Alert Inhibit json from DB : Error is \'%s\'\n\n", rapidjson::GetParseError_En(jdoc.GetParseError()));
			return;
		}	
		
		STRING_BUFFER<256>	strbuf;
		auto 			[errcode, id, pname] = add_inhibit(inhid, jdoc, strbuf, tcurr, tcreate, is_disabled);
		
		if (id && pname) {
			nadded++;

			DEBUGEXECN(1,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Alertmgr : Added Alert Inhibit from DB : \'%s\'\n", pname);
			);
		}	
		else {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to add new Alert Inhibit from DB : %s\n", strbuf.buffer()); 
		}
	};	

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_strview_cb(conn, std::move(gyres), is_completed, "Alert Inhibits", colarr, ncol, total_rows, rowcb);
		}
	);
	
	ret = dbmgrpool_.wait_one_response(30'000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			gshconnhdlr->db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (ret == 2) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alert Inhibit Query : Database Querying Timeout... Skipping...\n");
		}
		else {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alert Inhibit Query : Database Connection Error... Skipping...\n");
		}	

		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Added %u Alert Inhibit rules from DB\n", nadded);
}

void ALERTMGR::set_cfg_silences(const char *pfilename, const char *pcfg, size_t lencfg)
{
	JSON_DOCUMENT<32 * 1024, 8192>	doc;
	auto				& jdoc = doc.get_doc();
	JSON_ALLOCATOR			& allocator = jdoc.GetAllocator();

	jdoc.Parse(pcfg, lencfg);

	if (jdoc.HasParseError()) {
		char			ebuf[256];
		const char		*perrorstr = rapidjson::GetParseError_En(jdoc.GetParseError());

		ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid Alert Silence Config CFG_SILENCES_JSON : Error at offset %lu : Error is \'%s\'\n\n", 
			jdoc.GetErrorOffset(), perrorstr);

		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid JSON for Alert Silence Config CFG_SILENCES_JSON file %s", pfilename);
	}	

	if (false == jdoc.IsArray()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Silence Config CFG_SILENCES_JSON file %s : Needs to be a JSON Array type", pfilename);
	}	

	time_t				tcurr = time(nullptr);
	STRING_BUFFER<1024>		strbuf;
	int				nadded = 0;
	bool				bret;

	// First truncate existing silences...
	if (true) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Alert Silence Config CFG_SILENCES_JSON file %s seen : Deleting existing DB Silences first...\n", pfilename);

		auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
		
		if (!pconn) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to Postgres for Alert Silences truncation\n");

			gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
			gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);
		}
		else {
			pconn->pqexec_blocking("truncate table public.silencestbl;");
		}
	}	
	
	for (uint32_t i = 0; i < jdoc.Size(); i++) {

		STACK_JSON_WRITER<8096, 4096>	objwriter;
		const char			*pjson;
		uint32_t			szjson;

		jdoc[i].Accept(objwriter); 

		pjson 		= objwriter.get_string();
		szjson		= objwriter.get_size();

		strbuf.reset();

		auto 				[errcode, silid, pname] = add_silence(0, jdoc[i], strbuf, tcurr, tcurr);

		if (silid != 0) {
			nadded++;

			DEBUGEXECN(1,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Alertmgr : Added Alert Silence from Silence Config file : \'%s\'\n", pname);
			);
		}	
		else {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Failed to add new Alert Silence from Config file : %s", strbuf.buffer()); 
		}

		db_insert_silence(silid, pname, tcurr, pjson, szjson);
	}
		
	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Added %u Alert Silences from Silences Config file %s\n", nadded, pfilename);
}

void ALERTMGR::read_db_silences()
{
	auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Alert Silences info from db\n");

		gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return;
	}	

	int				ret, nadded = 0;
	bool				bret;
	time_t				tcurr = time(nullptr);

	const JSON_DB_MAPPING		*colarr[GY_ARRAY_SIZE(json_db_silences_arr)] {};
	size_t				ncol;
	STRING_BUFFER<1024>		strbuf;

	strbuf << "select silid, tcreated, disabled, silence from public.silencestbl limit " << ALERT_SILENCE::MAX_SILENCES << "\n;";

	bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.length());

	if (bret == false) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule query Postgres for Alert Silences info from db\n");

		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return;
	}	

	ncol 				= 4;

	colarr[0]			= &json_db_silences_arr[0];
	colarr[1]		 	= &json_db_silences_arr[2];
	colarr[2]			= &json_db_silences_arr[3];
	colarr[3]			= &json_db_silences_arr[4];

	static_assert(json_db_silences_arr[0].jsoncrc == FIELD_SILID);
	static_assert(json_db_silences_arr[2].jsoncrc == FIELD_TCREATED);
	static_assert(json_db_silences_arr[3].jsoncrc == FIELD_DISABLED);
	static_assert(json_db_silences_arr[4].jsoncrc == FIELD_SILENCE);

	const auto rowcb = [&](int numrow, const JSON_DB_MAPPING **pcolarr, std::string_view colview[], uint32_t ncol)
	{
		JSON_DOCUMENT<2048, 2048>	doc;
		auto				& jdoc = doc.get_doc();
		uint32_t			silid;
		time_t				tcreate;
		bool				is_disabled;
		
		if (colview[0].size() == 0) {
			return;
		}	

		silid = string_to_number<uint32_t>(colview[0].data(), 16);
		if (silid == 0) {
			return;
		}	

		if (colview[1].size() > 0) {
			tcreate = gy_iso8601_to_time_t(CHAR_BUF<64>(colview[1].data(), colview[1].size()).get());
		}
		else {
			tcreate = time(nullptr);
		}

		if (colview[2].size() > 0) {
			is_disabled = (*(colview[2].data()) == 't');
		}	
		else {
			is_disabled = false;
		}	

		if (colview[3].size() == 0) {
			return;
		}	
		if (jdoc.Parse(colview[3].data(), colview[3].size()).HasParseError()) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Invalid Alert Silence json from DB : Error is \'%s\'\n\n", rapidjson::GetParseError_En(jdoc.GetParseError()));
			return;
		}	
		
		STRING_BUFFER<256>	strbuf;
		auto 			[errcode, id, pname] = add_silence(silid, jdoc, strbuf, tcurr, tcreate, is_disabled);
		
		if (id && pname) {
			nadded++;

			DEBUGEXECN(1,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Alertmgr : Added Alert Silence from DB : \'%s\'\n", pname);
			);
		}	
		else {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to add new Alert Silence from DB : %s\n", strbuf.buffer()); 
		}
	};	

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_strview_cb(conn, std::move(gyres), is_completed, "Alert Silences", colarr, ncol, total_rows, rowcb);
		}
	);
	
	ret = dbmgrpool_.wait_one_response(30'000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			gshconnhdlr->db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (ret == 2) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alert Silence Query : Database Querying Timeout... Skipping...\n");
		}
		else {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alert Silence Query : Database Connection Error... Skipping...\n");
		}	

		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Added %u Alert Silence rules from DB\n", nadded);
}

void ALERTMGR::set_cfg_actions(const char *pfilename, const char *pcfg, size_t lencfg)
{
	JSON_DOCUMENT<32 * 1024, 8192>	doc;
	auto				& jdoc = doc.get_doc();
	JSON_ALLOCATOR			& allocator = jdoc.GetAllocator();

	jdoc.Parse(pcfg, lencfg);

	if (jdoc.HasParseError()) {
		char			ebuf[256];
		const char		*perrorstr = rapidjson::GetParseError_En(jdoc.GetParseError());

		ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid Alert Action Config CFG_ACTIONS_JSON : Error at offset %lu : Error is \'%s\'\n\n", 
			jdoc.GetErrorOffset(), perrorstr);

		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid JSON for Alert Action Config CFG_ACTIONS_JSON file %s", pfilename);
	}	

	if (false == jdoc.IsArray()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Action Config CFG_ACTIONS_JSON file %s : Needs to be a JSON Array type", pfilename);
	}	

	time_t				tcurr = time(nullptr);
	STRING_BUFFER<1024>		strbuf;
	int				nadded = 0;
	bool				bret;

	// First truncate existing actions...
	if (true) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Alert Action Config CFG_ACTIONS_JSON file %s seen : Deleting existing DB Actions first...\n", pfilename);

		auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
		
		if (!pconn) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to Postgres for Alert Actions truncation\n");

			gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
			gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);
		}
		else {
			pconn->pqexec_blocking("truncate table public.actionstbl;");
		}
	}	
	
	for (uint32_t i = 0; i < jdoc.Size(); i++) {

		STACK_JSON_WRITER<8096, 4096>	objwriter;
		const char			*pjson;
		uint32_t			szjson;

		jdoc[i].Accept(objwriter); 

		pjson 		= objwriter.get_string();
		szjson		= objwriter.get_size();

		strbuf.reset();

		auto 				[errcode, actionid, actttype, pname] = add_action(0, jdoc[i], strbuf, tcurr, tcurr);

		if (actionid && pname) {
			nadded++;

			DEBUGEXECN(1,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Alertmgr : Added Alert Action from Action Config file : \'%s\'\n", pname);
			);
		}	
		else {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Failed to add new Alert Action from Config file : %s", strbuf.buffer()); 
		}

		db_insert_update_action(actionid, pname, actttype, tcurr, pjson, szjson);
	}
		
	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Added %u Alert Action rules from Action Config file %s\n", nadded, pfilename);
}

void ALERTMGR::read_db_actions()
{
	auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Alert Actions info from db\n");

		gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return;
	}	

	int				ret, nadded = 0;
	bool				bret;
	time_t				tcurr = time(nullptr);

	const JSON_DB_MAPPING		*colarr[GY_ARRAY_SIZE(json_db_actions_arr)] {};
	size_t				ncol;
	STRING_BUFFER<1024>		strbuf;

	strbuf << "select actionid, acttype, tcreated, action from public.actionstbl limit " << ALERT_ACTION::MAX_ACTIONS << "\n;";

	bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.length());

	if (bret == false) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule query Postgres for Alert Actions info from db\n");

		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return;
	}	

	ncol 				= 4;

	colarr[0]			= &json_db_actions_arr[0];
	colarr[1]		 	= &json_db_actions_arr[2];
	colarr[2]			= &json_db_actions_arr[3];
	colarr[3]			= &json_db_actions_arr[4];

	static_assert(json_db_actions_arr[0].jsoncrc == FIELD_ACTIONID);
	static_assert(json_db_actions_arr[2].jsoncrc == FIELD_ACTTYPE);
	static_assert(json_db_actions_arr[3].jsoncrc == FIELD_TCREATED);
	static_assert(json_db_actions_arr[4].jsoncrc == FIELD_ACTION);

	const auto rowcb = [&](int numrow, const JSON_DB_MAPPING **pcolarr, std::string_view colview[], uint32_t ncol)
	{
		JSON_DOCUMENT<2048, 2048>	doc;
		auto				& jdoc = doc.get_doc();
		uint32_t			actionid;
		time_t				tcreate;
		AL_ACTION_E			acttype;

		if (colview[0].size() == 0) {
			return;
		}	

		actionid = string_to_number<uint32_t>(colview[0].data(), 16);
		if (actionid == 0) {
			return;
		}	

		if (colview[1].size() > 0) {
			acttype = string_to_action(colview[1].data(), false /* throw_on_err */);

			if (acttype == ACTION_MAX) {
				return;
			}	
		}
		else {
			return;
		}

		if (colview[2].size() > 0) {
			tcreate = gy_iso8601_to_time_t(CHAR_BUF<64>(colview[2].data(), colview[2].size()).get());
		}
		else {
			tcreate = tcurr;
		}

		if (colview[3].size() == 0) {
			return;
		}	
		if (jdoc.Parse(colview[3].data(), colview[3].size()).HasParseError()) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Invalid Alert Action config from DB : Error is \'%s\'\n\n", rapidjson::GetParseError_En(jdoc.GetParseError()));
			return;
		}	
		
		STRING_BUFFER<256>	strbuf;
		auto 			[errcode, id, type, pname] = add_action(actionid, jdoc, strbuf, tcurr, tcreate);
		
		if (id && pname) {
			nadded++;

			DEBUGEXECN(1,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Alertmgr : Added Alert Action from DB : \'%s\'\n", pname);
			);
		}	
		else {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to add new Alert Action from DB : %s\n", strbuf.buffer()); 
		}
	};	

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_strview_cb(conn, std::move(gyres), is_completed, "Alert Actions", colarr, ncol, total_rows, rowcb);
		}
	);
	
	ret = dbmgrpool_.wait_one_response(30'000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			gshconnhdlr->db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (ret == 2) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alert Action Query : Database Querying Timeout... Skipping...\n");
		}
		else {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alert Action Query : Database Connection Error... Skipping...\n");
		}	

		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Added %u Alert Action rules from DB\n", nadded);
}

void ALERTMGR::set_cfg_alertdefs(const char *pfilename, const char *pcfg, size_t lencfg)
{
	JSON_DOCUMENT<32 * 1024, 8192>	doc;
	auto				& jdoc = doc.get_doc();
	JSON_ALLOCATOR			& allocator = jdoc.GetAllocator();

	jdoc.Parse(pcfg, lencfg);

	if (jdoc.HasParseError()) {
		char			ebuf[256];
		const char		*perrorstr = rapidjson::GetParseError_En(jdoc.GetParseError());

		ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid Alert Definitions Config CFG_ALERTDEFS_JSON : Error at offset %lu : Error is \'%s\'\n\n", 
			jdoc.GetErrorOffset(), perrorstr);

		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid JSON for Alert Definitions Config CFG_ALERTDEFS_JSON file %s", pfilename);
	}	

	if (false == jdoc.IsArray()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Alert Definitions Config CFG_ALERTDEFS_JSON file %s : Needs to be a JSON Array type", pfilename);
	}	

	time_t				tcurr = time(nullptr);
	STRING_BUFFER<1024>		strbuf;
	int				nadded = 0;
	bool				bret;

	// First truncate existing Alertdefs...
	if (true) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Alert Definitions Config CFG_ALERTDEFS_JSON file %s seen : Deleting existing DB Alertdefs first...\n", pfilename);

		auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
		
		if (!pconn) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to Postgres for Alert Definitions truncation\n");

			gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
			gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);
		}
		else {
			pconn->pqexec_blocking("truncate table public.alertdeftbl;");
		}
	}	
	
	for (uint32_t i = 0; i < jdoc.Size(); i++) {

		STACK_JSON_WRITER<8096, 4096>	objwriter;
		const char			*pjson;
		uint32_t			szjson;

		jdoc[i].Accept(objwriter); 

		pjson 		= objwriter.get_string();
		szjson		= objwriter.get_size();

		strbuf.reset();

		auto 				[errcode, adefid, pnewdef] = add_alertdef(0, jdoc[i], jdoc.GetAllocator(), pjson, szjson, strbuf, tcurr, tcurr);

		if (adefid) {
			nadded++;

			DEBUGEXECN(1,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Alertmgr : Added Alert Definition from Alertdef Config file : \'%s\'\n", pnewdef->name());
			);
		}	
		else {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Failed to add new Alert Definition from Config file : %s", strbuf.buffer()); 
		}

		db_insert_alertdef(adefid, pnewdef->name(), tcurr, pjson, szjson, false);
	}
		
	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Added %u Alert Definitions from Alertdef Config file %s\n", nadded, pfilename);
}


void ALERTMGR::read_db_alert_defs()
{
	auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30000 /* max_msec_wait */, true /* reset_on_timeout */);

	if (!pconn) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to query Postgres for Alert Definitions info from db\n");

		gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return;
	}	

	int				ret, nadded = 0;
	bool				bret;
	time_t				tcurr = time(nullptr);

	const JSON_DB_MAPPING		*colarr[GY_ARRAY_SIZE(json_db_alertdef_arr)] {};
	size_t				ncol;
	STRING_BUFFER<1024>		strbuf;

	strbuf << "select adefid, tcreated, disabled, definition from public.alertdeftbl limit " << MAX_ALERT_DEFS << "\n;";

	bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.length());

	if (bret == false) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to schedule query Postgres for Alert Definitions info from db\n");

		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);
		return;
	}

	ncol 				= 4;

	colarr[0]			= &json_db_alertdef_arr[0];
	colarr[1]		 	= &json_db_alertdef_arr[2];
	colarr[2]			= &json_db_alertdef_arr[3];
	colarr[3]			= &json_db_alertdef_arr[4];

	static_assert(json_db_alertdef_arr[0].jsoncrc == FIELD_ADEFID);
	static_assert(json_db_alertdef_arr[2].jsoncrc == FIELD_TCREATED);
	static_assert(json_db_alertdef_arr[3].jsoncrc == FIELD_DISABLED);
	static_assert(json_db_alertdef_arr[4].jsoncrc == FIELD_DEFINITION);

	const auto rowcb = [&](int numrow, const JSON_DB_MAPPING **pcolarr, std::string_view colview[], uint32_t ncol)
	{
		JSON_DOCUMENT<2048, 2048>	doc;
		auto				& jdoc = doc.get_doc();
		uint32_t			adefid;
		time_t				tcreate;
		bool				is_disabled;
		
		if (colview[0].size() == 0) {
			return;
		}	

		adefid = string_to_number<uint32_t>(colview[0].data(), 16);
		if (adefid == 0) {
			return;
		}	

		if (colview[1].size() > 0) {
			tcreate = gy_iso8601_to_time_t(CHAR_BUF<64>(colview[1].data(), colview[1].size()).get());
		}
		else {
			tcreate = tcurr;
		}

		if (colview[2].size() > 0) {
			is_disabled = (*(colview[2].data()) == 't');
		}	
		else {
			is_disabled = false;
		}	

		if (colview[3].size() == 0) {
			return;
		}	
		if (jdoc.Parse(colview[3].data(), colview[3].size()).HasParseError()) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Invalid Alert Definition json from DB : Error is \'%s\'\n\n", rapidjson::GetParseError_En(jdoc.GetParseError()));
			return;
		}	
		
		STRING_BUFFER<256>	strbuf;
		auto 			[errcode, id, pnewdef] = add_alertdef(adefid, jdoc, jdoc.GetAllocator(), colview[3].data(), colview[3].size(), strbuf, tcurr, tcreate, is_disabled);
		
		if (id && pnewdef) {
			nadded++;

			DEBUGEXECN(1,
				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Alertmgr : Added Alert Definition from DB : \'%s\'\n", pnewdef->name());
			);
		}	
		else {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to add new Alert Definition from DB : %s\n", strbuf.buffer()); 
		}
	};	

	pconn->set_single_row_mode();

	pconn->set_resp_cb(
		[&, colarr, total_rows = 0, ncol](GyPGConn & conn, GyPGresult gyres, bool is_completed) mutable -> bool
		{
			return default_db_strview_cb(conn, std::move(gyres), is_completed, "Alert Definition", colarr, ncol, total_rows, rowcb);
		}
	);
	
	ret = dbmgrpool_.wait_one_response(30'000, pconn.getintconn());

	if (ret != 0) {
		if (ret == 2) {
			gshconnhdlr->db_stats_.ndbquery_timeout_.fetch_add_relaxed(1);
		}

		if (ret == 2) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alert Definition Query : Database Querying Timeout... Skipping...\n");
		}
		else {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alert Definition Query : Database Connection Error... Skipping...\n");
		}	

		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Added %u Alert Definitions from DB\n", nadded);
}

void ALERTMGR::read_db_alert_info()
{
	thrid_ = pthread_self();

	if (true) {	
		const char			*penv = getenv("CFG_INHIBITS_JSON");
		std::string			jsonstr;

		if (penv && *penv) {
			jsonstr = read_file_to_string(penv, GY_UP_MB(32), 0, "Alert Inhibits CFG_INHIBITS_JSON config file ");
		}	

		if (jsonstr.empty()) {
			try {
				read_db_inhibits();
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while trying to read Alert Inhibit Info from DB : %s\n", GY_GET_EXCEPT_STRING); 
			);
		}
		else {
			// Set all inhibits from config file ignoring existing inhibits in db
			set_cfg_inhibits(penv, jsonstr.data(), jsonstr.size());
		}	
	}

	if (true) {	
		const char			*penv = getenv("CFG_SILENCES_JSON");
		std::string			jsonstr;

		if (penv && *penv) {
			jsonstr = read_file_to_string(penv, GY_UP_MB(32), 0, "Alert Silences CFG_SILENCES_JSON config file ");
		}	

		if (jsonstr.empty()) {
			try {
				read_db_silences();
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while trying to read Alert Silences Info from DB : %s\n", GY_GET_EXCEPT_STRING); 
			);
		}
		else {
			// Set all silences from config file ignoring existing silences in db
			set_cfg_silences(penv, jsonstr.data(), jsonstr.size());
		}	
	}

	if (true) {	
		const char			*penv = getenv("CFG_ACTIONS_JSON");
		std::string			jsonstr;

		if (penv && *penv) {
			jsonstr = read_file_to_string(penv, GY_UP_MB(32), 0, "Alert Action CFG_ACTIONS_JSON config file ");
		}	

		if (jsonstr.empty()) {
			try {
				read_db_actions();
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while trying to read Alert Actions Info from DB : %s\n", GY_GET_EXCEPT_STRING); 
			);
		}
		else {
			// Set all actions from config file ignoring existing actions in db
			set_cfg_actions(penv, jsonstr.data(), jsonstr.size());
		}	
	}

	if (true) {	
		const char			*penv = getenv("CFG_ALERTDEFS_JSON");
		std::string			jsonstr;

		if (penv && *penv) {
			jsonstr = read_file_to_string(penv, GY_UP_MB(32), 0, "Alert Definitions CFG_ALERTDEFS_JSON config file ");
		}	

		if (jsonstr.empty()) {
			try {
				read_db_alert_defs();
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while trying to read Alert Definitions Info from DB : %s\n", GY_GET_EXCEPT_STRING); 
			);
		}
		else {
			// Set all alertdefs from config file ignoring existing alertdefs in db
			set_cfg_alertdefs(penv, jsonstr.data(), jsonstr.size());
		}	
	}


	send_shyama_all_alertdefs();
}	

NUMBER_CRITERION AlertStatFilter::astat_num_field(const JSON_DB_MAPPING *pfield) const
{
	// First check if field is from Alert subsystem itself
	switch (pfield->jsoncrc) {
	
	case FIELD_ALERTTIME	:	return NUMBER_CRITERION((int64_t)astat.tstart_);

	case FIELD_NREPEATS 	:	return NUMBER_CRITERION((int)astat.info_.nrepeats_);

	case FIELD_EXPIRY	:	return NUMBER_CRITERION((int64_t)astat.tforce_close_);

	case FIELD_TACTION	:	return NUMBER_CRITERION((int64_t)astat.taction_);

	case FIELD_TCLOSE	:	
					if (astat.tclose_ > 0) {
						return NUMBER_CRITERION((int64_t)astat.tclose_);
					}
					else {
						return {};
					}

	default			:	break;	

	}	

	// Field is from JSON

	if (!pjdoc_) {
		return {};
	}

	bool			is_timestamp = false;

	if (pfield->jsontype != JSON_NUMBER) {
		if (0 != std::memcmp(pfield->dbtype, "timestamptz", GY_CONST_STRLEN("timestamptz"))) {
			return {};
		}

		is_timestamp = true;
	}	

	auto			it = pjdoc_->FindMember(pfield->jsonfield);
	if (it == pjdoc_->MemberEnd()) {
		return {};
	}	

	if (!it->value.IsNumber()) {
		if (is_timestamp && it->value.IsString()) {
			time_t			tval;
			
			tval = gy_iso8601_to_time_t(it->value.GetString());

			if (tval != 0) {
				return NUMBER_CRITERION(tval);
			}	
		}

		return {};
	}	

	if (pfield->numtype == NUM_DOUBLE) {
		return NUMBER_CRITERION(it->value.GetDouble());
	}	

	int64_t				i64;
	
	if (it->value.IsDouble()) {
		i64 = (int64_t)it->value.GetDouble();
	}
	else {
		i64 = (int64_t)it->value.GetInt64();
	}	

	switch (pfield->numtype) {

	case NUM_INT32		:	return NUMBER_CRITERION((int32_t)i64);

	case NUM_INT16		: 	return NUMBER_CRITERION((int16_t)i64);

	case NUM_INT8		:	return NUMBER_CRITERION((int8_t)i64);

	case NUM_INT64		:	
	default			:	
					return NUMBER_CRITERION(i64);
	}	
}

std::pair<const char *, uint32_t> AlertStatFilter::astat_str_field(const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf, bool *pisvalid) const
{
	if (pisvalid) {
		*pisvalid = true;
	}

	// First check if field is from Alert subsystem itself
	switch (pfield->jsoncrc) {
	
	case FIELD_ALERTID 	:
					if (tbuf && szbuf > 8) {
						std::pair<const char *, uint32_t>	p;

						p.first		= tbuf;
						p.second 	= snprintf(tbuf, szbuf, "%08x", astat.info_.alertid_);

						return p;
					}
					return {};

	case FIELD_ALERTNAME	:	
					if (astat.pdef_) {
						return { astat.pdef_->name(), astat.pdef_->name_.length() };
					}	
					return {};

	case FIELD_ASTATE	:	return astate_to_stringlen(astat.state_);

	case FIELD_SEVERITY	:	return severity_to_stringlen(astat.fseverity_);

	case FIELD_ADEFID 	:
					if (tbuf && szbuf > 8) {
						std::pair<const char *, uint32_t>	p;

						p.first		= tbuf;
						p.second 	= snprintf(tbuf, szbuf, "%08x", astat.info_.adef_id_);

						return p;
					}
					return {};

	case FIELD_ACTIONS	:	return { actionview_.data(), actionview_.size() };

	case FIELD_ANNOT	:	return { annotview_.data(), annotview_.size() };

	case FIELD_ACKNOTES	:	return {};	// Acknotes will only be updated to DB

	case FIELD_SUBSYS	:	
					if (astat.pdef_) {
						return { astat.pdef_->pasubsys_, strlen(astat.pdef_->pasubsys_) };
					}	
					return {};

	case FIELD_LABELS	:	
					if (astat.pdef_) {
						return { astat.pdef_->labels_.data(), astat.pdef_->labels_.size() };
					}	
					return {};

	case FIELD_ALERTDATA	:	
					if (astat.palertdata_) {
						return { astat.palertdata_->data(), astat.palertdata_->size() };
					}	
					return {};

	default			:	break;	

	}	

	// Field is from JSON

	if (pfield->jsontype != JSON_STRING) {
		if (pisvalid) {
			*pisvalid = false;
		}

		return {};
	}	

	if (!pjdoc_) {
		if (pisvalid) {
			*pisvalid = false;
		}

		return {};
	}

	auto			it = pjdoc_->FindMember(pfield->jsonfield);
	if (it == pjdoc_->MemberEnd()) {
		if (pisvalid) {
			*pisvalid = false;
		}

		return {};
	}	

	if (!it->value.IsString()) {
		if (pisvalid) {
			*pisvalid = false;
		}

		return {};
	}	

	return { it->value.GetString(), it->value.GetStringLength() };
}

BOOL_CRITERION AlertStatFilter::astat_bool_field(const JSON_DB_MAPPING *pfield) const
{
	// First check if field is from Alert subsystem itself
	switch (pfield->jsoncrc) {
	
	default			:	break;	

	}	

	// Field is from JSON

	if (pfield->jsontype != JSON_BOOL) {
		return {};
	}	

	if (!pjdoc_) {
		return {};
	}

	auto			it = pjdoc_->FindMember(pfield->jsonfield);
	if (it == pjdoc_->MemberEnd()) {
		return {};
	}	

	if (!it->value.IsBool()) {
		return {};
	}	

	return it->value.GetBool();
}

bool AlertStatFilter::astat_field_to_string(const JSON_DB_MAPPING *pfield, STR_WR_BUF & strbuf) const
{
	auto			jsontype = pfield->jsontype;
	bool			is_timestamp = false;

	assert(pfield);

	/*
	 * Evaluate Alert Subsystem timestamp fields as Number formatted
	 */
	if ((0 == std::memcmp(pfield->dbtype, "timestamptz", GY_CONST_STRLEN("timestamptz"))) && 
		(nullptr != get_jsoncrc_mapping(pfield->jsoncrc, json_db_alerts_arr, GY_ARRAY_SIZE(json_db_alerts_arr)))) {
		
		jsontype 	= JSON_NUMBER;
		is_timestamp 	= true;
	}

	switch (jsontype) {

	case JSON_NUMBER :
		if (true) {
			auto		numc = astat_num_field(pfield);

			if (numc.is_valid()) {
				if (!is_timestamp) {
					numc.to_string(strbuf, pfield, true /* only_data */);
				}
				else {
					time_t		tsec = numc.get_int64();

					strbuf.append(gy_localtime_iso8601_sec(tsec).get());
				}	

				return true;
			}
		}	
		break;
		
	case JSON_STRING :
		if (true) {
			char		tbuf[2048];
			bool		isvalid = false;

			auto		p = astat_str_field(pfield, tbuf, sizeof(tbuf), &isvalid);

			if (p.second > 0) {
				strbuf << p;
				return true;
			}	

			return isvalid;
		}	
		break;
	
	case JSON_BOOL :
		if (true) {
			auto		b = astat_bool_field(pfield);

			if (b.is_valid()) {
				b.to_string(strbuf, pfield, true /* only_data */);
				return true;
			}
		}	
		break;

	default :
		break;
	}	

	return false;
}


void AlertStatFilter::get_alerts_json(STR_WR_BUF & strbuf, bool ign_alertdata, bool ign_nulls) const
{
	size_t				maxcols = (ign_alertdata ? GY_ARRAY_SIZE(json_db_alerts_arr) - 1 : GY_ARRAY_SIZE(json_db_alerts_arr));
	bool				bret = false, lupd = false;

	strbuf << '{';

	for (size_t i = 0; i < maxcols; ++i) {
		STRING_BUFFER<2048>		tbuf;
		const auto			*pcol = json_db_alerts_arr + i;

		if (lupd) {
			strbuf << ',';
		}		

		bret = astat_field_to_string(pcol, tbuf);

		if ((false == bret) && ign_nulls) {
			lupd = false;
			continue;
		}

		lupd = true;

		strbuf << '\"';
		strbuf.append(pcol->jsonfield, pcol->szjson);
		strbuf << "\":";

		if (bret) {
			if (pcol->jsontype == JSON_STRING) {
				auto			escjson = gy_escape_json<12 * 1024>(tbuf.data(), tbuf.size(), false /* throw_on_error */);

				strbuf.append(escjson.data(), escjson.size());
			}
			else {
				strbuf << tbuf;
			}	
		}	
		else {
			if (pcol->jsontype == JSON_STRING) {
				strbuf << "\"\"";
			}
			else if (pcol->jsontype == JSON_NUMBER) {
				strbuf << 0;
			}	
			else if (pcol->jsontype == JSON_BOOL) {
				strbuf << false;
			}	
		}	
	}

	if (strbuf[strbuf.size() - 1] == ',') {
		strbuf--;
	}

	strbuf << '}';	
}	

CRIT_RET_E AlertStatFilter::filter_match(const CRITERIA_SET & criteria) const
{
	auto num_field = [this](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) -> NUMBER_CRITERION
	{
		return astat_num_field(pfield);
	};

	auto str_field = [this](const JSON_DB_MAPPING *pfield, char * tbuf, size_t szbuf, SUBSYS_CLASS_E subsys) -> std::pair<const char *, uint32_t>
	{
		return astat_str_field(pfield, tbuf, szbuf);
	};	

	auto bool_field = [this](const JSON_DB_MAPPING *pfield, SUBSYS_CLASS_E subsys) -> BOOL_CRITERION
	{
		return astat_bool_field(pfield);
	};

	return criteria.match_criteria(num_field, str_field, bool_field, tcurr_);
}	

ALERT_GROUP::ALERT_GROUP(uint64_t groupid, uint32_t grp_waitsec, time_t tcurr)
	: groupid_(groupid), tstart_(tcurr), groupwaitsec_(grp_waitsec)
{}	

ALERT_STATS::ALERT_STATS(comm::ALERT_STAT_INFO & info, intrusive_ptr<ALERTDEF> pdef)
	: tstart_(info.talert_), pdef_(std::move(pdef)), info_(info)
{
	if (!pdef_) {
		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "New Alert Stat Object with invalid Alert Def param");
	}	

	tforce_close_ 	= tstart_ + pdef_->forceclosesec_;
	
	if (pdef_->repeataftersec_ > 0) {
		trepeat_alert_	= tstart_ + pdef_->repeataftersec_;
	}
}	


bool ALERT_SILENCE::is_alert_silenced(const AlertStatFilter & filter, time_t tcurr) const
{
	if (!is_disabled() && (true == mutetimes_.is_mute_time(tcurr)) && (CRIT_FAIL != filter.filter_match(match_))) {
		return true;
	}	

	return false;
}	

std::pair<uint32_t, bool> ALERTMGR::is_alert_silenced(const AlertStatFilter & filter) const
{
	time_t			tcurr = filter.tcurr_;

	if (tany_silence_end_ + 30 < tcurr) {
		return {0, false};
	}	
	
	for (const auto & [silid, psilence] : silencemap_) {
		if (bool(psilence) && true == psilence->is_alert_silenced(filter, tcurr)) {
			return {psilence->silid_, true};
		}	
	}
	
	return {0, false};
}	

// Returns {is_inhib, causesinhibit}
std::pair<bool, bool> ALERT_INHIBIT::is_alert_inhibited(const AlertStatFilter & filter)
{
	ALERT_STATS			*pstat = &filter.astat;

	if (is_disabled()) {
		return {false, false};
	}	

	if (!srcstatslist_.empty() && (CRIT_PASS == filter.filter_match(target_match_))) {
		STRING_BUFFER<2048>		strbuf;

		for (const auto & src : srcstatslist_) {
			const auto 		& cols = src.cols_;
			
			if (!src.pstat_ || src.pstat_->is_deleted() || cols.size() != equal_cols_.size()) {
				continue;
			}	

			for (size_t i = 0; i < equal_cols_.size(); ++i) {

				size_t				srcsz = cols[i].size();

				if (0 == srcsz) {
					continue;
				}	

				const auto			*pcol = equal_cols_[i];

				strbuf.reset();

				filter.astat_field_to_string(pcol, strbuf);	
				
				if (strbuf.size() == srcsz && (0 == memcmp(strbuf.data(), cols[i].data(), srcsz))) {
					return {true, false};
				}	
			}
		}
	}	

	if (CRIT_PASS != filter.filter_match(src_match_)) {
		return {false, false};
	}	
	else {
		if (srcstatslist_.size() >= MAX_SRC_ASTATS) {
			srcstatslist_.pop_back();
		}

		SrcStats			& src = srcstatslist_.emplace_front(pstat);
		STRING_BUFFER<2048>		strbuf;

		src.cols_.reserve(equal_cols_.size());

		for (const auto *pcol : equal_cols_) {
			strbuf.reset();

			filter.astat_field_to_string(pcol, strbuf);	
			
			src.cols_.emplace_back(strbuf.data(), strbuf.size());
		}
		
		return {false, true};
	}
}	

// Returns {inhid, is_inhib}
std::pair<uint32_t, bool> ALERTMGR::is_alert_inhibited(const AlertStatFilter & filter) const
{
	std::optional<SmallVec<ALERT_INHIBIT *, 16>>	ivec;

	for (const auto & [inhid, pinhibit] : inhibitmap_) {
		if (!pinhibit) {
			continue;
		}	

		auto		[is_inhib, causesinhibit] = pinhibit->is_alert_inhibited(filter);

		if (is_inhib) {
			// Remove any src inhibit entries added
			if (ivec) {
				for (auto *pin : *ivec) {
					pin->srcstatslist_.pop_front();		// Since added to front
				}	
			}

			return {inhid, true};
		}

		if (causesinhibit) {
			if (!ivec) {
				ivec.emplace();
			}

			ivec->emplace_back(pinhibit.get());
		}
	}
	
	if (bool(ivec)) {
		ALERT_STATS			*pstat = &filter.astat;
		
		pstat->src_inhib_vec_.reserve(ivec->size());

		for (auto *pin : *ivec) {
			pstat->src_inhib_vec_.emplace_back(pin->inhid_);
		}	
	}

	return {0, false};
}	

bool ALERTMGR::send_msg_to_dbhdlr(ADB_MSG && dbmsg)
{
	int				ntries = 0;
	bool				bret;

	do { 
		bret = dbhdlr_.aqueue_.write(std::move(dbmsg));
	} while (bret == false && ntries++ < 2);

	if (bret == false) {
		dbhdlr_.npoolblocks_++;
		return false;
	}

	return true;
}

// Must be called after send_multi_action_msg() completed
bool ALERTMGR::send_alert_to_dbhdlr(const AlertStatFilter & filter)
{
	ALERT_STATS			& astat = filter.astat;

	if (!astat.palertdata_) {
		return false;
	}

	STRING_BUFFER<8192>		strbuf;
	auto				timebuf = gy_localtime_iso8601_sec(filter.astat.tstart_);
	ADB_MSG				dbmsg; 
	uint32_t			offlens[GY_ARRAY_SIZE(json_db_alerts_arr)];
	int				ntries = 0;
	bool				bret;

	static_assert(json_db_alerts_arr[0].jsoncrc == FIELD_ALERTTIME);

	static_assert(json_db_alerts_arr[GY_ARRAY_SIZE(json_db_alerts_arr) - 1].jsoncrc == FIELD_ALERTDATA);

	nalerts_++;

	offlens[0] = 0;
	strbuf << timebuf.get() << "\x0";

	for (size_t i = 1; i < GY_ARRAY_SIZE(json_db_alerts_arr) - 1; ++i) {
		STRING_BUFFER<2048>		tbuf;
		const auto			*pcol = json_db_alerts_arr + i;	

		offlens[i]			= strbuf.size();

		bret = filter.astat_field_to_string(pcol, tbuf);	
		if (bret && tbuf.size()) {
			strbuf << tbuf << "\x0";
		}	
		else {
			if (0 == strcmp(pcol->dbtype, "timestamptz")) {
				offlens[i] = ~0u;
			}
			else {
				strbuf << "\x0";
			}
		}	
	}	
	
	if (false == strbuf.is_overflow()) {
		dbmsg.talert_			= filter.astat.tstart_;

		dbmsg.alertstr_.assign(strbuf.data(), strbuf.size());
	
		const char			*porig = dbmsg.alertstr_.data();

		for (size_t i = 0; i < GY_ARRAY_SIZE(json_db_alerts_arr) - 1; ++i) {
			if (offlens[i] != ~0u) {
				dbmsg.parambufs_[i]	= porig + offlens[i];
			}
			else {
				dbmsg.parambufs_[i]	= nullptr;
			}	
		}	
		
		dbmsg.parambufs_[GY_ARRAY_SIZE(json_db_alerts_arr) - 1]	= astat.palertdata_->data();

		dbmsg.palertdata_	= astat.palertdata_;
		dbmsg.alertid_		= astat.get_alertid();
		dbmsg.mtype_		= ADB_MSG::MsgNew;

		return send_msg_to_dbhdlr(std::move(dbmsg));
	}	
	else {
		dbhdlr_.nstrbufovf_++;
		return false;
	}	
}

bool ADEF_ACTION::to_string(STR_WR_BUF & strbuf) const noexcept
{
	if (!actionshr_) {
		return false;
	}	

	strbuf << "{ \"type\" : \"" << action_to_stringlen(actionshr_->acttype_) << "\", \"config\" : " << actionshr_->config_;

	strbuf.appendfmt(", \"configid\" : \"%08x\"", actionshr_->configid_);

	if (newconfig_.size()) {
		strbuf << ", \"newconfig\" : " << newconfig_;
	}	
	
	strbuf << " }";

	return true;
}	

bool ALERTMGR::send_close_action_msg(ALERT_STATS &astat, bool is_force_close)
{
	STRING_BUFFER<8192>		strbuf;
	ACT_MSG				actmsg;
	int				ntries = 0, nact = 0;
	bool				bret;

	if (astat.tclose_ == 0) {
		return false;
	}	

	strbuf << "{ \"etype\" : \"action\", \"actions\" : [ ";

	bret = false;

	for (const auto & paction : astat.actionvec_) {
		if (!paction || false == paction->send_resolved_) {
			continue;
		}

		if (bret) {
			strbuf << ',';
		}

		bret = paction->to_string(strbuf);
		
		nact += bret;
	}	
	
	strbuf << " ], \"close\" : true, \"expired\" : " << is_force_close << ", \"alerts\" : [ ";

	if (nact == 0) {
		return true;
	}

	if (strbuf.is_overflow()) {
		acthdlr_.nstrbufovf_++;
		return false;
	}	

	actmsg.conf_json_ 	= std::make_unique<char []>(strbuf.size() + 1);
	actmsg.lenconf_		= strbuf.size();
	actmsg.atype_	 	= ACT_MSG::ACloseAlert;

	std::memcpy(actmsg.conf_json_.get(), strbuf.data(), strbuf.size() + 1);

	strbuf.reset();

	AlertStatFilter(astat, astat.tstart_).get_alerts_json(strbuf, true /* ign_alertdata */, true /* ign_nulls */);
		
	if (strbuf.is_overflow()) {
		acthdlr_.nstrbufovf_++;
		return false;
	}

	ssize_t			s = strbuf.size();

	while (s > 0 && strbuf[s - 1] != '}') {
		s--;
		strbuf--;
	}		

	strbuf--;

	if (strbuf.size() == 0) {
		return false;
	}	

	actmsg.nalerts_ 	= 1;
	actmsg.alertstrarr_[0] 	= std::make_unique<char []>(strbuf.size() + 1);
	actmsg.lenalertstr_[0] 	= strbuf.size();

	std::memcpy(actmsg.alertstrarr_[0].get(), strbuf.data(), strbuf.size() + 1);

	do { 
		bret = acthdlr_.aqueue_.write(std::move(actmsg));
	} while (bret == false && ntries++ < 2);

	if (bret == false) {
		acthdlr_.npoolblocks_++;
		return false;
	}
	
	return true;
}

bool ALERTMGR::send_multi_action_msg(const intrusive_ptr<ALERT_STATS> *pstatarr, uint32_t nstats, time_t tcurr, const AlertStatFilter *pfilterarr)
{
	using Actionset 		= INLINE_STACK_HASH_SET<ADEF_ACTION *, 1024, GY_JHASHER<ADEF_ACTION *>>;

	Actionset			aset;

	assert(pstatarr && nstats <= MAX_ONE_ACTION_ALERTS);

	if (nstats > MAX_ONE_ACTION_ALERTS) {
		nstats = MAX_ONE_ACTION_ALERTS;
	}	

	for (uint32_t i = 0; i < nstats; ++i) {
		ALERT_STATS		*pstat;

		pstat = pstatarr[i].get();

		if (!pstat || pstat->is_deleted() || !pstat->palertdata_) {
			continue;
		}	

		pstat->state_ 		= ASTATE_ACTIVE;
		pstat->taction_		= tcurr;

		for (size_t j = 0; j < pstat->actionvec_.size(); ++j) {
			if (!pstat->actionvec_[j]) {
				continue;
			}	

			aset.emplace(pstat->actionvec_[j].get());
		}	
	}	

	if (aset.size() == 0) {
		return false;
	}	

	STRING_BUFFER<10 * 1024>	strbuf;
	ACT_MSG				actmsg;
	int				ntries = 0;
	bool				bret;

	strbuf << "{ \"etype\" : \"action\", \"actions\" : [ ";

	bret = false;

	for (const auto *paction : aset) {
		if (bret) {
			strbuf << ',';
		}	

		bret = paction->to_string(strbuf);
	}	
	
	strbuf << " ], \"close\" : false, \"expired\" : false, \"alerts\" : [ ";

	if (strbuf.is_overflow()) {
		acthdlr_.nstrbufovf_++;
		return false;
	}	

	actmsg.conf_json_ 	= std::make_unique<char []>(strbuf.size() + 1);
	actmsg.lenconf_		= strbuf.size();
	actmsg.atype_	 	= ACT_MSG::ANewAlert;

	std::memcpy(actmsg.conf_json_.get(), strbuf.data(), strbuf.size() + 1);

	for (uint32_t i = 0; i < nstats; ++i) {
		ALERT_STATS			*pstat;

		pstat = pstatarr[i].get();

		if (!pstat || pstat->is_deleted() || !pstat->palertdata_) {
			continue;
		}	
		
		strbuf.reset();

		if (!pfilterarr) {
			AlertStatFilter(*pstat, pstat->tstart_).get_alerts_json(strbuf, true /* ign_alertdata */, true /* ign_nulls */);
		}
		else {
			pfilterarr[i].get_alerts_json(strbuf, true /* ign_alertdata */, true /* ign_nulls */);
		}	
		
		// Add alertdata key
		ssize_t			s = strbuf.size();

		while (s > 0 && strbuf[s - 1] != '}') {
			s--;
			strbuf--;
		}

		strbuf--;
		
		if (strbuf.size() == 0) {
			continue;
		}

		strbuf << ", \"";
		strbuf.append(json_db_alerts_arr[GY_ARRAY_SIZE(json_db_alerts_arr) - 1].jsonfield, json_db_alerts_arr[GY_ARRAY_SIZE(json_db_alerts_arr) - 1].szjson);
		strbuf << "\":";

		if (strbuf.is_overflow()) {
			acthdlr_.nstrbufovf_++;
			continue;
		}

		actmsg.alertstrarr_[actmsg.nalerts_] 	= std::make_unique<char []>(strbuf.size() + 1);
		actmsg.lenalertstr_[actmsg.nalerts_] 	= strbuf.size();

		std::memcpy(actmsg.alertstrarr_[actmsg.nalerts_].get(), strbuf.data(), strbuf.size() + 1);

		actmsg.alertdataarr_[actmsg.nalerts_] 	= pstat->palertdata_;

		actmsg.nalerts_++;
	}

	if (actmsg.nalerts_ == 0) {
		return false;
	}	

	do { 
		bret = acthdlr_.aqueue_.write(std::move(actmsg));
	} while (bret == false && ntries++ < 2);

	if (bret == false) {
		acthdlr_.npoolblocks_++;
		return false;
	}
	
	return true;
}	

void ALERTMGR::send_alert_now(const intrusive_ptr<ALERT_STATS> & pstatint, const AlertStatFilter & filter, time_t tcurr)
{
	ALERT_STATS		& astat = filter.astat;

	if (astat.palertdata_) {
		send_multi_action_msg(&pstatint, 1, tcurr, &filter);

		send_alert_to_dbhdlr(filter);
	}	

	astat.clear_strings();
}

bool ALERTMGR::cleanup_alert_stat(uint32_t alertid, ALERT_STATS & astat, time_t tclose, bool is_close, bool is_force_close) noexcept
{
	/*
	 * Clear the pgroup_ and remove the astat from group vector.
	 * Also check if src_inhib_vec_ is populated and if so, erase this from
	 * the inhibit objects as well. If after the group vector removal, the group
	 * becomes empty, cancel any schedules and delete the group.
	 * Then if is_close == true, update the DB and send alert actions
	 * for send_resolved == true actions
	 */
	GY_SCOPE_EXIT {
		astat.set_deleted();
	};

	try {
		bool			fired_alert = (astat.state_ >= ASTATE_ACTIVE);

		if (is_close) {
			astat.tclose_ 		= tclose;
			astat.state_		= (is_force_close ? ASTATE_EXPIRED : ASTATE_RESOLVED);
			astat.is_force_close_	= is_force_close;
		}

		if (astat.pgroup_) {
			auto			& group =  *astat.pgroup_.get();

			for (auto it = group.statvec_.begin(); it != group.statvec_.end(); ++it) {	
				if (it->get() == &astat) {
					group.statvec_.erase(it);
					break;
				}
			}	

			if (group.statvec_.size() == 0 && !group.is_deleted()) {
				if (group.tnextchkusec_) {
					erase_group_timemap(&group, group.tnextchkusec_);
				}

				group.set_deleted();
				agroupmap_.erase(group.groupid_);
			}	

			astat.pgroup_.reset();
		}	
		
		for (uint32_t inhid : astat.src_inhib_vec_) {
			auto			it = inhibitmap_.find(inhid);

			if (it != inhibitmap_.end()) {
				const auto		& pinhibit = it->second;

				if (pinhibit) {
					auto			& srclist = pinhibit->srcstatslist_;

					for (auto sit = srclist.begin(); sit != srclist.end(); ) {
						if (sit->pstat_.get() == &astat) {
							sit = srclist.erase(sit);
							break;
						}	
						else {
							++sit;
						}	
					}	
				}	
			}	
		}	

		if (is_close == false) {
			// Its a repeat alert
			return true;
		}	
		
		DEBUGEXECN(1,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Closing Alert : %s\n", astat.print_string().get());
		);

		if (fired_alert) {
			if (!is_force_close) {
				send_close_action_msg(astat, is_force_close);
			}
			
			send_msg_to_dbhdlr(ADB_MSG(astat.tstart_, tclose, astat.get_alertid(), is_force_close ? ADB_MSG::MsgExpired : ADB_MSG::MsgResolved));
		}

		return true;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while cleaning up Alert Stat : %s\n", GY_GET_EXCEPT_STRING);
		);

		return false;
	);
}

bool ALERTMGR::erase_group_timemap(const ALERT_GROUP *pgroup, uint64_t keyusec)
{
	int			nerase = 0;
	bool			bret = false;
	auto 			range = atimemap_.equal_range(keyusec);
	
	for (auto it = range.first; it != range.second; ) {
		if (it->second.pgroup_.get() == pgroup) {
			it = atimemap_.erase(it);

			nerase++;
			bret = true;
		}
		else {
			++it;
		}	
	}	
	
	if (nerase > 0) {
		multierase_ = true;
	}	

	return bret;
}	

void ALERTMGR::set_astat_group(const intrusive_ptr<ALERT_STATS> & pstatint, const intrusive_ptr<ALERTDEF> & pdefintr, const AlertStatFilter & filter, time_t tcurr, uint64_t currtusec)
{
	if (pdefintr->groupwaitsec_ == 0) {
		// No grouping
		pstatint->taction_	= pstatint->tstart_;
		pstatint->groupid_	= 0;
		return;
	}

	STRING_BUFFER<2048>		strbuf;
	uint64_t			groupid;
	bool				bret;
	
	bret = pdefintr->groupby_.get_group_str(filter, strbuf);
	if (false == bret || strbuf.size() == 0) {
		// No grouping
		pstatint->taction_	= pstatint->tstart_;
		pstatint->groupid_	= 0;
		return;
	}	

	groupid = gy_cityhash64(strbuf.data(), strbuf.size());
	
	auto			[git, gtrue] = agroupmap_.try_emplace(groupid);

	if (gtrue || !git->second || git->second->is_deleted()) {
		git->second = new ALERT_GROUP(groupid, pdefintr->groupwaitsec_, tcurr);
	}	
	
	auto			& group = *(git->second.get());

	pstatint->groupid_	= groupid;
	pstatint->pgroup_	= &group;
	pstatint->state_ 	= ASTATE_GROUP_WAIT;
	
	group.statvec_.emplace_back(pstatint);
	
	if (group.state_ == AGROUP_IDLE) {
		group.tnextchkusec_ 	= currtusec + pdefintr->groupwaitsec_ * GY_USEC_PER_SEC;
		pstatint->taction_	= tcurr + pdefintr->groupwaitsec_;

		atimemap_.emplace(std::piecewise_construct, std::forward_as_tuple(group.tnextchkusec_), 
							std::forward_as_tuple(intrusive_ptr<ALERT_GROUP>(&group), ACmd::CmdGroupSendAlerts)); 
		group.state_ = AGROUP_WAIT;

		DEBUGEXECN(1,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "New Alert seen : %s : Adding new Alert Group with Group Wait %u sec : Alerts in last min %u last hour %u\n",
				pstatint->print_string().get(), pdefintr->groupwaitsec_, nalerts_min_, nalerts_hour_);
		);
	}
	else {
		// Already in Group Wait
		pstatint->taction_	= group.tnextchkusec_/GY_USEC_PER_SEC;

		DEBUGEXECN(1,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "New Alert seen : %s : Adding to existing Group with Wait of %ld sec : #Alerts in group = %lu : "
				"Alerts in last min %u last hour %u\n", 
				pstatint->print_string().get(), pstatint->taction_ - tcurr, group.statvec_.size(), nalerts_min_, nalerts_hour_);
		);
	}	
}	

STRING_BUFFER<512> ALERT_STATS::print_string() const noexcept
{
	STRING_BUFFER<512>		strbuf;
	auto				pdef = pdef_.get();

	strbuf.appendfmt("%sAlert ID \'%08x\' for \'%s\' : Severity \'%s\' : Subsystem \'%s\'", 
			info_.nrepeats_ > 0 ? "Repeat " : "", get_alertid(), pdef ? pdef->name() : "", 
			severity_to_stringlen(fseverity_).first, pdef ? pdef->pasubsys_ : "");

	return strbuf;
}	

bool ALERTMGR::add_alert_stat(comm::ALERT_STAT_INFO & stat, time_t tcurr, uint64_t currtusec, const char *srcstr)
{
	if (stat.alertid_ == 0 || stat.adef_id_ == 0 || stat.lenjson_ <= 1) {
		DEBUGEXECN(10,
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alertmgr received invalid Alert with invalid id or definition id\n");
		);

		ninvalid_alerts_++;
		return false;
	}
	
	time_t			texpiry = 0;
	bool			is_repeat = false;

	auto			it = astatmap_.find(stat.alertid_);

	if (it != astatmap_.end()) {
		ALERT_STATS		*pastat;
			
		pastat = it->second.get();

		if (stat.nrepeats_ > 0)  {
			if (pastat && !pastat->is_deleted()) {
				// Allow only repeat alerts when its time for repeat alerts and also only if not already acked

				if (pastat->info_.adef_id_ != stat.adef_id_) {

					DEBUGEXECN(1,
						WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alertmgr received Repeat Alert with mismatch in definition id : "
								"Alertid \'%08x\' : Original Definition ID \'%08x\' : New Definition ID \'%08x\'\n",
								stat.alertid_, pastat->info_.adef_id_, stat.adef_id_);
					);

					ninvalid_alerts_++;
					return false;
				}	
				else if (pastat->tstart_ + MIN_ALERT_REPEAT_INTERVAL_SEC - 5 < tcurr && pastat->state_ != ASTATE_ACKED) {
					
					is_repeat = true;
					if (pastat->tforce_close_ > tcurr) {
						texpiry = pastat->tforce_close_;
					}	

					cleanup_alert_stat(stat.alertid_, *pastat, tcurr, false /* is_close */, false /* is_force_close */);
				}
				else {
					DEBUGEXECN(1,
						WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alertmgr received repeat Alert but Repeat Time not yet reached. Skipping repeat alert of %s\n",
							pastat->print_string().get());
					);

					nalerts_skipped_++;
					return false;
				}
			}
			
			astatmap_.erase(it);
		}	
		else {
			DEBUGEXECN(1,
				WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alertmgr received Repeat Alert with invalid alert id : Alertid \'%08x\' not found\n",
						stat.alertid_);
			);

			ninvalid_alerts_++;
			return false;
		}	
	}	
	
	auto				dit = adefmap_.find(stat.adef_id_);
	if (dit == adefmap_.end()) {
		DEBUGEXECN(1,
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alertmgr received Alert with invalid definition id : Alertid \'%08x\' : Definition ID \'%08x\'\n",
				stat.alertid_, stat.adef_id_);
		);

		ninvalid_alerts_++;
		return false;
	}	

	auto				pdefintr = dit->second;		// Copy

	if (!pdefintr || pdefintr->is_deleted() || !pdefintr->is_enabled()) {
		DEBUGEXECN(1,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Alertmgr received Alert but Definition is disabled : Skipping Alertid \'%08x\' : Definition ID \'%08x\'\n",
				stat.alertid_, stat.adef_id_);
		);

		nalerts_skipped_++;
		return false;
	}	

	const char			*pdefname = pdefintr->name();

	// Ignore all alerts started over 24 hours old or already expired
	if (stat.talert_ < tcurr - 3600 * 24 || stat.talert_ + pdefintr->forceclosesec_ < tcurr) {
		DEBUGEXECN(1,
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alertmgr received Alert but Alert already expired : Alertid \'%08x\' : Name \'%s\'\n", stat.alertid_, pdefname);
		);

		ninvalid_alerts_++;
		return false;
	}	

	if (false == check_set_alerts_allowed(tcurr, pdefname)) {
		return false;
	}	

	char				*pjson = (char *)(&stat + 1);
	JSON_DOCUMENT<16 * 1024, 4096>	doc;
	auto				& jdoc = doc.get_doc();

	if (jdoc.Parse(pjson, stat.lenjson_).HasParseError()) {
		WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alertmgr : Invalid new Alert for Alert ID \'%08x\' name \'%s\' : Alert Json invalid\n\n", 
			stat.alertid_, pdefname);

		DEBUGEXECN(11,
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alert JSON sent was : \'%s\'\n", pjson);
		);

		ninvalid_alerts_++;
		return false;
	}	
	
	intrusive_ptr<ALERT_STATS>	pstatint(new ALERT_STATS(stat, pdefintr));
	AlertStatFilter			filter(*pstatint.get(), jdoc, tcurr);
	STRING_BUFFER<800>		actstrbuf;
	bool				is_suppress = false;

	if (is_repeat && texpiry > tcurr) {
		// Keep the expiry same as the original alert
		pstatint->tforce_close_ = texpiry;
	}

	/*
	 * First get the severity, annotations, actions.
	 * Then check if Silencing or Inhibition active and then add the 
	 * alert to its group and set the timer entry to send the alert to the action/db handlers
	 */
	pstatint->fseverity_ 		= pdefintr->severity_.get_severity(filter);

	auto				annot = pdefintr->annotations_.get_annotations(filter);

	filter.set_annot_view(annot.data(), annot.size());
	
	pstatint->actionvec_		= pdefintr->get_actions(filter, actstrbuf);

	if (pstatint->actionvec_.size() == 0) {
		DEBUGEXECN(1,
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Alertmgr Skipping new Alert due to no valid Alert Actions :Alert Definition name \'%s\'\n", pdefname);
		);	

		nalerts_skipped_++;

		pstatint->set_deleted();

		// pstatint will be deallocated
		return false;
	}	

	filter.set_action_view(actstrbuf.data(), actstrbuf.size());

	auto				[silid, is_silenced] = is_alert_silenced(filter);

	if (is_silenced == true) {
		pstatint->state_	= ASTATE_SUPPRESSED;
		is_suppress		= true;

		nalerts_silenced_++;
	}	
	else {
		auto			[inhid, is_inhib] = is_alert_inhibited(filter);

		if (is_inhib) {
			pstatint->state_	= ASTATE_SUPPRESSED;
			is_suppress		= true;
			
			nalerts_inhib_++;
		}	
	}	

	/*
	 * NOTE : Currently for Suppressed Alerts we do not store entries to DB...
	 * We also do not store these alerts to the astatmap_ 
	 */
	if (is_suppress) {
		DEBUGEXECN(1,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Alertmgr Skipping new Alert due to %s : Alert info : %s\n",
				is_silenced ? "Silencing" : "Inhibition", pstatint->print_string().get());
		);

		nalerts_skipped_++;

		pstatint->set_deleted();

		// pstatint will be deallocated
		return false;
	}	
	
	/*
	 * Now add the entry to astatmap_
	 */
	astatmap_.try_emplace(stat.alertid_, pstatint);

	pstatint->palertdata_ = std::make_shared<std::string>(pjson, stat.lenjson_ - 1);

	if (pstatint->tstart_ < tleastalert_) {
		tleastalert_ = pstatint->tstart_;
	}	

	set_astat_group(pstatint, pdefintr, filter, tcurr, currtusec);

	if (pstatint->groupid_ == 0) {
		// Need to send the alert immediately

		DEBUGEXECN(1,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "New Alert seen : %s : Alert is not Grouped and fired immediately : Alerts in last min %u last hour %u\n",
				pstatint->print_string().get(), nalerts_min_, nalerts_hour_);
		);

		send_alert_now(pstatint, filter, tcurr);
	}	
	else {
		if (annot.size()) {
			pstatint->annotstr_ = std::make_unique<char []>(annot.size() + 1);
			pstatint->lenannot_ = annot.size();

			std::memcpy(pstatint->annotstr_.get(), annot.data(), annot.size() + 1);
		}

		if (actstrbuf.size()) {
			pstatint->actionstr_ = std::make_unique<char []>(actstrbuf.size() + 1);
			pstatint->lenaction_ = actstrbuf.size();

			std::memcpy(pstatint->actionstr_.get(), actstrbuf.data(), actstrbuf.size() + 1);
		}	
	}	

	return true;
}	

void ALERTMGR::agroup_send_alerts(ALERT_GROUP & group)
{
	try {
		auto			&statvec = group.statvec_;
		
		if (statvec.size() == 0) {
			return;
		}	

		time_t			tcurr = time(nullptr);
		uint32_t		nelems;
		auto			*pstattmp = statvec.data(), *pstatstart = pstattmp, *pstatend = pstatstart + statvec.size();
		
		// Send Alerts in batches of MAX_ONE_ACTION_ALERTS
		for (; pstattmp < pstatend; ) {
			nelems = std::min<uint32_t>(pstatend - pstattmp, MAX_ONE_ACTION_ALERTS);

			send_multi_action_msg(pstattmp, nelems, tcurr);
			pstattmp += nelems;
		}	

		for (pstattmp = pstatstart; pstattmp < pstatend; ++pstattmp) {
			if (pstattmp && pstattmp->get() && false == (*pstattmp)->is_deleted()) {
				auto			& astat = *(*pstattmp).get();

				send_alert_to_dbhdlr(AlertStatFilter(astat, astat.tstart_));
				
				astat.clear_strings();
			}
		}
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1,
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while sending Alertmr Grouped Alerts : %s\n", GY_GET_EXCEPT_STRING);
		);
	);

	group.set_deleted();

	agroupmap_.erase(group.groupid_);
}	

void ALERTMGR::set_alerts_disabled(time_t tcurr, int64_t disable_sec)
{
	if (disable_sec <= 0) {
		return;
	}

	tdisable_end_ = tcurr + disable_sec;

	if (disable_sec < 5) {
		return;
	}

	/*
	 * Send Alert Disable event to all Madhava's and local Shyama
	 */
	size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(SM_ALERT_STAT_DISABLE);

	auto				puniq = make_refcnt_uniq(fixed_sz);
	void				*palloc = puniq.get();

	COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
	EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
	auto				*pstat = reinterpret_cast<SM_ALERT_STAT_DISABLE *>(pnot + 1);

	new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, COMM_HEADER::MS_HDR_MAGIC);
	
	new (pnot) EVENT_NOTIFY(NOTIFY_SM_ALERT_STAT_DISABLE, 1);
	
	new (pstat) SM_ALERT_STAT_DISABLE(tdisable_end_);
	 
	gshconnhdlr->send_all_madhava_event(std::move(puniq), fixed_sz, phdr->get_pad_len());

	gshconnhdlr->pshalerthdlr_->set_disable_alerts(tdisable_end_);
}

bool ALERTMGR::check_set_alerts_allowed(time_t tcurr, const char *pdefname)
{
	if (tcurr < tdisable_end_) {

		DEBUGEXECN(1,
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alertmgr received Alert but currently all alerts are disabled for next %ld sec : "
					"Skipping Alert for \'%s\'\n", tdisable_end_ - tcurr, pdefname);
		);

		nalerts_skipped_++;
		return false;
	}	

	if (tmin_start_ + 60 > tcurr) {
		if (nalerts_min_ + 1 >= MAX_TOTAL_ALERTS_PER_MIN) {
			
			// Disable Alerts for next 3 min
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Alertmgr Disabling all new Alerts for next 180 sec as too many alerts %u seen in last minute (%ld sec) : "
						"Alerts in last hour = %u\n", nalerts_min_, tcurr - tmin_start_, nalerts_hour_);
			nalerts_skipped_++;
			
			set_alerts_disabled(tcurr, 180);
			return false;
		}	
	}	
	else {
		tmin_start_ 	= tcurr;
		nalerts_min_ 	= 0;
	}	

	if (thour_start_ + 3600 > tcurr) {
		if (nalerts_hour_ + 1 >= MAX_TOTAL_ALERTS_PER_HOUR) {
			nalerts_skipped_++;

			// Disable Alerts for next 30 min
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Alertmgr Disabling all new Alerts for next 30 minutes as too many alerts %u seen in last hour (%ld min) : "
						"Alerts in last minute = %u\n", nalerts_hour_, (tcurr - thour_start_)/60, nalerts_min_);
			nalerts_skipped_++;
			
			set_alerts_disabled(tcurr, 1800);
			return false;
		}	
	}	
	else {
		thour_start_ 	= tcurr;
		nalerts_hour_ 	= 0;
	}	

	if (astatmap_.size() >= MAX_UNRESOLVED_ALERTS) {
		DEBUGEXECN(1,
			WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alertmgr received Alert but currently too many alerts are active (%lu) : "
					"Skipping Alert for \'%s\'\n", astatmap_.size(), pdefname);
		);

		nalerts_skipped_++;
		return false;
	}	

	nalerts_min_++;
	nalerts_hour_++;

	return true;
}

void ALERTMGR::handle_alert_stat_info(const char *srcstr, comm::ALERT_STAT_INFO *pstat, int nevents, uint8_t *pendptr)
{
	auto			*ptmp = pstat;
	uint64_t		currtusec = get_usec_time();
	time_t			tcurr = currtusec/GY_USEC_PER_SEC;
	int			nadded = 0, nerr = 0;

	for (int i = 0; i < nevents && (uint8_t *)ptmp < pendptr; ++i, ptmp = (ALERT_STAT_INFO *)((uint8_t *)ptmp + ptmp->get_elem_size())) {
		try {
			nadded += (int)add_alert_stat(*ptmp, tcurr, currtusec, srcstr);	
		}
		GY_CATCH_EXCEPTION(
			if (++nerr < 4) {
				ERRORPRINT_OFFLOAD("Exception occurred while handling new Alert Stats notify in Alertmgr : %s\n", GY_GET_EXCEPT_STRING);
			}
		);
	}
	
	if (nadded + nerr > 0) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Alertmgr : Added %d New Alerts from Alert Stats received from %s\n", nadded, srcstr);
	}
}	


void ALERTMGR::handle_alert_stat_close(const char *srcstr, comm::ALERT_STAT_CLOSE *pstat, int nevents, uint8_t *pendptr)
{
	auto			*ptmp = pstat;
	int			nclose = 0, nforce = 0, nskip = 0;

	for (int i = 0; i < nevents; ++i, ++ptmp) {
		try {
			auto			it = astatmap_.find(ptmp->alertid_);

			if (it != astatmap_.end()) {
				ALERT_STATS		*pastat;
					
				pastat = it->second.get();

				if (pastat && !pastat->is_deleted()) {
					cleanup_alert_stat(ptmp->alertid_, *pastat, ptmp->tcurr_, true /* is_close */, ptmp->is_force_close_);

					nclose++;
					nforce += ptmp->is_force_close_;
				}
					
				astatmap_.erase(it);
			}	
			else {
				nskip++;
			}	
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINT_OFFLOAD("Exception occurred while handling Alert Close notify in Alertmgr : %s\n", GY_GET_EXCEPT_STRING);
		);
	}
	
	if (nclose > 0) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Alertmgr received %d Closed Alerts Stats with %d Forced Close received from %s\n", nclose, nforce, srcstr);
	}
}

void ALERTMGR::handle_node_alert_stat_update(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery, time_t tcurr)
{
	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Status Update Command received with missing data payload");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Status Update Command received with invalid data : data member not of JSON Object type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	const auto			& obj = it->value.GetObject();
	
	it = obj.FindMember("alertid");

	if (it == obj.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Status Update Command received with missing field \'alertid\'");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	else if (false == it->value.IsString()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Status Update Command received with invalid data : \'alertid\' member not of JSON string type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	

	const char		*pid = it->value.GetString(), *packnotes = nullptr;
	time_t			tstart = 0;
	uint32_t		alertid, lenack = 0;
	bool			bret;

	bret = string_to_number(pid, alertid, nullptr, 16);
	if (!bret) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Status Update Command received with invalid data : \'alertid\' specified is invalid : not in ID string format");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	// Must have astate as either acked or resolved (for manual resolve cases)
	it = obj.FindMember("astate");

	if (it == obj.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Status Update Command received with missing field \'astate\'");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	else if (false == it->value.IsString()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Status Update Command received with invalid data : \'astate\' member not of JSON String type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	

	auto			newstate = astate_from_string(it->value.GetString(), it->value.GetStringLength());

	if (newstate == ASTATE_UNKNOWN) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Status Update Command received with invalid \'astate\' : \'%s\' not a valid state", it->value.GetString());

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	else if (!(newstate == ASTATE_ACKED || newstate == ASTATE_RESOLVED)) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Status Update Command received with invalid \'astate\' : \'%s\' state cannot be set using update", 
					it->value.GetString());

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	

	it = obj.FindMember("acknotes");

	if (it != obj.MemberEnd()) {
		if (false == it->value.IsString()) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Status Update Command received with field \'acknotes\' not in JSON String format");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}	

		packnotes = it->value.GetString();
		lenack = it->value.GetStringLength();
	}
	

	STACK_JSON_WRITER<2048>		writer;
	ERR_CODES_E			errcode = ERR_STATUS_OK;
	char				ebuf[255];
	bool				to_update_db = false;
	uint32_t			len = 0;

	*ebuf = 0;

	writer.StartObject();

	writer.KeyConst("status");

	auto				mit = astatmap_.find(alertid);

	if (mit == astatmap_.end()) {
		errcode	= ERR_DATA_NOT_FOUND;
		len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert ID \'%s\' not found : ID may be invalid or the Alert has already Resolved", pid);
	}	
	else {
		if (mit->second.get()) {
			auto			*pastat = mit->second.get();

			if (newstate == ASTATE_RESOLVED) {
				// Check if manual resolve set

				if (!pastat->pdef_ || !pastat->pdef_->is_manual_resolve()) {
					errcode	= ERR_INVALID_REQUEST;
					len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert ID \'%s\' Manual Resolve requested but Alert Definition has manualresolve set to false", pid);
				}	
				else if (pastat->is_deleted() || pastat->state_ >= ASTATE_RESOLVED) {
					len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert ID \'%s\' Manual Resolve requested but Alert has already expired or resolved", pid);
				}	
				else {
					cleanup_alert_stat(alertid, *pastat, tcurr, true /* is_close */, false /* is_force_close */);	// Will also update the DB
					astatmap_.erase(mit);

					len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert ID \'%s\' set as resolved", pid);
				}
			}	
			else {
				// ASTATE_ACKED
				if (pastat->is_deleted() || pastat->state_ >= ASTATE_RESOLVED) {
					len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert ID \'%s\' Ack requested but Alert has already expired or resolved", pid);
				}	
				else if (pastat->state_ == ASTATE_ACTIVE || pastat->state_ == ASTATE_ACKED) {

					if (pastat->nacks_ >= 64) {
						errcode	= ERR_INVALID_REQUEST;
						len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert ID \'%s\' Too many Acks already received : Max 64 Acks per Alert", pid);
					}	
					else {
						// Update DB only for new state change or if new Ack Notes seen
						if (pastat->state_ == ASTATE_ACTIVE || lenack > 0) {
							to_update_db 	= true;
						}	

						pastat->nacks_++;
						pastat->state_ 	= ASTATE_ACKED;
						tstart 		= pastat->tstart_;
						len 		= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert ID \'%s\' set as Acked : "
										"Repeat Alerts for this Alert ID will be skipped till resolution or expiry", pid);
					}
				}	
				else {
					errcode	= ERR_INVALID_REQUEST;
					len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert ID \'%s\' Ack requested but Alert is not currently in a Active State", pid);
				}	
			}	
		}
		else {
			len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert ID \'%s\' Alert %s requested but Alert has already expired or resolved", 
							pid, newstate == ASTATE_ACKED ? "Ack" : "Manual Resolve");
		}	
	}	
	
	if (errcode != ERR_STATUS_OK) {
		writer.StringConst("failed");
	
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(ebuf, len);
	}	
	else {
		writer.StringConst("ok");

		writer.KeyConst("msg");
		writer.String(ebuf, len);

		DEBUGEXECN(1,
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Node Alert State Update received : %s\n", ebuf);
		);	
	}	
		
	writer.EndObject();

	// Send the status
	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();

	bret = gshconnhdlr->send_query_response(connshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	
	if (false == to_update_db) {
		return;
	}	

	/*
	 * Now update the DB 
	 */
	std::string			alertstr;

	if (packnotes && lenack) {
		alertstr.assign(packnotes, lenack);
	}	

	send_msg_to_dbhdlr(ADB_MSG(tstart, tcurr, alertid, ADB_MSG::MsgAck, std::move(alertstr)));
}	

std::tuple<ERR_CODES_E, uint32_t, const ALERTDEF *> ALERTMGR::add_alertdef(uint32_t adefid, GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator, const char *pjson, size_t szjson, \
							STR_WR_BUF & strbuf, time_t tcurr, time_t tcreate, bool is_disabled) noexcept
{
	const char 		*pname = nullptr;

	try {
		/*
		 * We first do a quick validation of json and reformat it to the format needed.
		 * After validation, we add the alertdef to the table and then save the alert to db
		 */
		
		if (!jdoc.IsObject()) {
			strbuf << "Invalid Alert Add Definition JSON : Require a JSON Object";
			return {ERR_INVALID_REQUEST, 0, nullptr};
		}	

		if (adefmap_.size() >= MAX_ALERT_DEFS) {
			strbuf.appendfmt("Alert Definition Add received but Max Alert Definition Count is already reached %lu : "
						"Cannot add new Alert Definitions : Please delete any unused ones first", adefmap_.size());
			return {ERR_INVALID_REQUEST, 0, nullptr};
		}

		static constexpr const char	*reqfields[] = {
			"alertname", "subsys", "action", 
		};	

		for (const char *pkey : reqfields) {
			if (false == jdoc.HasMember(pkey)) {
				strbuf.appendfmt("Alert Definition Add Command received but mandatory field \'%s\' missing", pkey);
				return {ERR_INVALID_REQUEST, 0, nullptr};
			}	
		}	

		auto 			pdefuniq = std::make_unique<ALERTDEF>(jdoc, allocator, pjson, szjson, adefid, tcurr, tcreate, is_disabled);
		
		auto			pdef = pdefuniq.get();
		adefid 			= pdef->get_defid();	// As passed adefid may be 0
		pname 			= pdef->name();

		auto 			[it, success] = adefmap_.try_emplace(adefid);
		if (!success) {
			strbuf << "Alert Definition name \'" << pname << "\' already exists : Please use a different name or delete the existing one first";
			return {ERR_CONFLICTS, 0, nullptr};
		}	
		else {
			it->second 	= pdefuniq.release();
		}	

		strbuf << "Added new Alert Definition name \'" << pname << "\' successfully : Definition ID is ";
		strbuf.appendfmt("\'%08x\'", adefid);

		return {ERR_STATUS_OK, adefid, pdef};
	}
	GY_CATCH_EXPRESSION(
		int			ecode = GY_GET_EXCEPT_CODE();

		if (ecode == 0) ecode = ERR_SERV_ERROR;
	
		strbuf << "New Alert Definition failed due to : " << GY_GET_EXCEPT_STRING;
		return {ERR_CODES_E(ecode), 0, nullptr};
	);
}


void ALERTMGR::handle_node_alertdef_add(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, JSON_ALLOCATOR & allocator, comm::QUERY_CMD *pquery)
{
	STACK_JSON_WRITER<2048>		writer;
	STRING_BUFFER<1024>		strbuf;
	time_t				tcurr = time(nullptr);

	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Definition Add Command received with missing data payload");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Definition Add Command received with invalid data : data member not of JSON Object type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	STACK_JSON_WRITER<12 * 1024, 4096>	objwriter;
	const char				*pjson;
	uint32_t				szjson;

	it->value.Accept(objwriter); 

	pjson 		= objwriter.get_string();
	szjson		= objwriter.get_size();

	auto 				[errcode, adefid, pnewdef] = add_alertdef(0, it->value, allocator, pjson, szjson, strbuf, tcurr, tcurr);

	writer.StartObject();

	writer.KeyConst("status");

	if (adefid == 0) {
		writer.StringConst("failed");
	
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(strbuf);
	}	
	else {
		writer.StringConst("ok");

		writer.KeyConst("msg");
		writer.String(strbuf);
	}	
		
	writer.EndObject();

	// Send the status
	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();
	bool				bret;

	bret = gshconnhdlr->send_query_response(connshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	
	if (adefid == 0 || !pnewdef) {
		WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to add new Alert Definition from Node : %s\n", strbuf.buffer());
		return; 
	}	

	/*
	 * Send Alert Def Add event to all Madhava's or Shyama if Shyama Handled
	 */
	
	if (false == pnewdef->is_shyama_handled()) {
		constexpr size_t		fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY);

		auto				puniq = make_refcnt_uniq(fixed_sz + sizeof(SM_ALERT_ADEF_NEW) + szjson + 1 + 7);
		void				*palloc = puniq.get();

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
		auto				*pstat = reinterpret_cast<SM_ALERT_ADEF_NEW *>(pnot + 1);

		new (pstat) SM_ALERT_ADEF_NEW(adefid, szjson + 1, pnewdef->state_.load(mo_relaxed), pnewdef->asubsys_, pnewdef->isrealtime_, pnewdef->is_partha_handled());

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz + pstat->get_elem_size(), COMM_HEADER::MS_HDR_MAGIC);
		
		new (pnot) EVENT_NOTIFY(NOTIFY_SM_ALERT_ADEF_NEW, 1);

		std::memcpy((uint8_t *)(pstat + 1), pjson, szjson);
		((uint8_t *)(pstat + 1))[szjson] = 0;
		 
		gshconnhdlr->send_all_madhava_event(std::move(puniq), phdr->get_act_len(), phdr->get_pad_len());
	}
	else {
		gshconnhdlr->pshalerthdlr_->send_new_alertdef(tcurr, pjson, szjson + 1, adefid, pnewdef->asubsys_, pnewdef->isrealtime_);
	}	

	/*
	 * Now update the DB with the new def
	 */
	bret = db_insert_alertdef(adefid, pnewdef->name(), tcurr, pjson, szjson, !pnewdef->is_enabled());

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Added new Alert Definition \'%s\' successfully\n", pnewdef->name());
}

bool ALERTMGR::db_insert_alertdef(uint32_t adefid, const char *name, time_t tcreate, const char *pjson, uint32_t szjson, bool is_disabled)
{
	auto				timebuf = gy_localtime_iso8601_sec(tcreate);
	bool				bret;
	auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
	
	if (!pconn) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to insert new Alert Definition to DB\n");

		gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return false;
	}	

	char				idbuf[20], tbuf[2];
	const char			*params[5] { idbuf, name, timebuf.get(), tbuf, pjson };
	
	snprintf(idbuf, sizeof(idbuf), "%08x", adefid);

	tbuf[0] = pgintbool[is_disabled & 0x1];
	tbuf[1] = 0;

	const char			qcmd[] = "insert into public.alertdeftbl values ($1::char(8), $2::text, $3::timestamptz, $4::boolean, $5::text) "
							"on conflict(adefid) do update set (disabled, definition) = (excluded.disabled, excluded.definition);\n";

	bret = PQsendQueryParams(pconn->get(), qcmd, GY_ARRAY_SIZE(params), nullptr, params, nullptr, nullptr, 0);

	if (bret == false) {
		gshconnhdlr->db_stats_.nalertdef_failed_.fetch_add_relaxed(1);

		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to update DB with New Alert Definition due to %s\n", PQerrorMessage(pconn->get()));
		return false;
	}	

	pconn->set_resp_cb(
		[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
		{
			if (is_completed) {
				if (conn.is_within_tran()) {
					conn.pqexec_blocking("Rollback Work;");
				}						
				conn.make_available();
				return true;
			}	
			
			if (true == gyres.is_error()) {
				gshconnhdlr->db_stats_.nalertdef_failed_.fetch_add_relaxed(1);

				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to update DB with New Alert Definition due to %s\n", gyres.get_error_msg());
				return false;
			}	

			return true;
		}
	);

	return true;
}

void ALERTMGR::handle_node_alertdef_delete(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery)
{
	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Definition Delete Command received with missing data payload");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Definition Delete Command received with invalid data : data member not of JSON Object type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	const char			*pdefid = nullptr, *pname = nullptr;
	uint32_t			adefid = 0;
	bool				bret;
	const auto			& obj = it->value.GetObject();
	
	it = obj.FindMember("adefid");

	if (it == obj.MemberEnd()) {
		
		it = obj.FindMember("alertname");
		
		if (it == obj.MemberEnd() || (false == it->value.IsString())) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Definition Delete Command received with missing mandatory fields \'adefid\' or \'alertname\'");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}

		pname = it->value.GetString();

		adefid = get_adef_id(pname, it->value.GetStringLength());
	}	
	else if (false == it->value.IsString()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Definition Delete Command received with invalid data : \'adefid\' member not of JSON string type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	else {
		pdefid = it->value.GetString();

		bret = string_to_number(pdefid, adefid, nullptr, 16);
		if (!bret) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Definition Delete Command received with invalid data : \'adefid\' specified is invalid : not in ID string format");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}
	}	

	STACK_JSON_WRITER<2048>		writer;
	bool				to_update_all = false, is_realtime = false;
	ADEF_HDLR_E			ahdlr = AHDLR_MADHAVA;
	ERR_CODES_E			errcode = ERR_STATUS_OK;
	char				ebuf[255];
	size_t				len;


	writer.StartObject();

	writer.KeyConst("status");

	auto				mit = adefmap_.find(adefid);

	if (mit == adefmap_.end()) {
		errcode = ERR_DATA_NOT_FOUND;
		len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert Definition %s \'%s\' not found", pdefid ? "ID" : "Name", pdefid ? pdefid : pname);

		writer.StringConst("failed");
	
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(ebuf, len);
	}	
	else {
		if (mit->second && !mit->second->is_deleted()) {
			auto			*pdef = mit->second.get();

			len = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Deleted Alert Definition \'%s\'", pdef->name());

			pdef->state_.store(ADEFSTATE_DISABLED, mo_relaxed);

			to_update_all = true;
			is_realtime = pdef->isrealtime_;
			ahdlr = pdef->ahdlr_;

			pdef->set_deleted();
			
			// NOTE : We do not delete intrusive_ptr refs within Alert Stats at this moment
		}
		else {
			len = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Deleted Alert Definition");
		}	

		adefmap_.erase(mit);

		writer.StringConst("ok");

		writer.KeyConst("msg");
		writer.String(ebuf, len);
	}	
		
	writer.EndObject();

	// Send the status
	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();

	bret = gshconnhdlr->send_query_response(connshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	
	if (false == to_update_all) {
		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Node Alert Definition Deletion received : %s\n", ebuf);

	/*
	 * Send Alert Def Deletion event to all Madhava's or Shyama if Shyama Handled
	 */
	if (ahdlr != AHDLR_SHYAMA) { 
		size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(SM_ALERT_ADEF_UPD);

		auto				puniq = make_refcnt_uniq(fixed_sz);
		void				*palloc = puniq.get();

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
		auto				*pstat = reinterpret_cast<SM_ALERT_ADEF_UPD *>(pnot + 1);

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, COMM_HEADER::MS_HDR_MAGIC);
		
		new (pnot) EVENT_NOTIFY(NOTIFY_SM_ALERT_ADEF_UPD, 1);
		
		new (pstat) SM_ALERT_ADEF_UPD(adefid, ALERT_ADEF_DELETE, is_realtime, ahdlr == AHDLR_PARTHA);

		gshconnhdlr->send_all_madhava_event(std::move(puniq), fixed_sz, phdr->get_pad_len());
	}
	else {
		gshconnhdlr->pshalerthdlr_->send_alertdef_update(adefid, ALERT_ADEF_DELETE, is_realtime);
	}	

	/*
	 * Now update the DB 
	 */
	db_update_alertdef(&adefid, 1, ALERT_ADEF_DELETE);
}


void ALERTMGR::handle_node_alertdef_update(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery)
{
	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Definition Update Command received with missing data payload");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Definition Update Command received with invalid data : data member not of JSON Object type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	const char			*pdefid = nullptr, *pname = nullptr;
	uint32_t			adefid = 0;
	bool				bret;
	const auto			& obj = it->value.GetObject();
	
	it = obj.FindMember("adefid");

	if (it == obj.MemberEnd()) {
		it = obj.FindMember("alertname");
		
		if (it == obj.MemberEnd() || (false == it->value.IsString())) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Definition Update Command received with missing mandatory fields \'adefid\' or \'alertname\'");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}

		pname = it->value.GetString();

		adefid = get_adef_id(pname, it->value.GetStringLength());
	}	
	else if (false == it->value.IsString()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Definition Update Command received with invalid data : \'adefid\' member not of JSON string type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	else {
		pdefid = it->value.GetString();

		bret = string_to_number(pdefid, adefid, nullptr, 16);
		if (!bret) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Definition Update Command received with invalid data : \'adefid\' specified is invalid : not in ID string format");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}
	}	

	ADEF_HDLR_E			ahdlr = AHDLR_MADHAVA;
	bool				disabled, to_update_all = false, is_realtime = false;

	it = obj.FindMember("disabled");

	if (it == obj.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Definition Update Command received with missing field \'disabled\' : Please specify \'disabled\' as true or false");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	

	if (it->value.IsBool()) {
		disabled = it->value.GetBool();
	}
	else if (it->value.IsString()) {
		const char		*pval = it->value.GetString();

		if (0 == strcmp(pval, "false")) {
			disabled = false;
		}
		else if (0 == strcmp(pval, "true")) {
			disabled = true;
		}
		else {
			goto derr;
		}	
	}	
	else {
derr :		
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Definition Update Command received with invalid data : \'disabled\' member not of JSON boolean type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	

	STACK_JSON_WRITER<2048>		writer;
	ERR_CODES_E			errcode = ERR_STATUS_OK;
	ALERT_MSG_TYPE 			newstate = ALERT_ADEF_DISABLE;
	char				ebuf[255];
	size_t				len;

	writer.StartObject();

	writer.KeyConst("status");

	auto				mit = adefmap_.find(adefid);

	if (mit == adefmap_.end()) {
		errcode	= ERR_DATA_NOT_FOUND;
		len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert Definition %s \'%s\' not found", pdefid ? "ID" : "Name", pdefid ? pdefid : pname);

		writer.StringConst("failed");
	
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(ebuf, len);
	}	
	else {
		if (mit->second && !mit->second->is_deleted()) {
			auto			*pdef = mit->second.get();

			len = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Setting Alert Definition \'%s\' status to %s", pdef->name(), disabled ? "Disabled" : "Enabled");

			if (disabled && pdef->state_.load(mo_relaxed) != ADEFSTATE_DISABLED) {
				pdef->state_.store(ADEFSTATE_DISABLED, mo_relaxed);
				newstate = ALERT_ADEF_DISABLE;

				to_update_all = true;
			}	
			else if (!disabled && pdef->state_.load(mo_relaxed) == ADEFSTATE_DISABLED) {
				pdef->state_.store(ADEFSTATE_ENABLED, mo_relaxed);
				newstate = ALERT_ADEF_ENABLE;

				to_update_all = true;
			}	

			is_realtime = pdef->isrealtime_;
			ahdlr = pdef->ahdlr_;
		}
		else {
			len = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Setting Alert Definition status to %s", disabled ? "Disabled" : "Enabled");
		}	

		writer.StringConst("ok");

		writer.KeyConst("msg");
		writer.String(ebuf, len);
	}	
		
	writer.EndObject();

	// Send the status
	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();

	bret = gshconnhdlr->send_query_response(connshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	
	if (false == to_update_all) {
		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Node Alert Definition Update received : %s\n", ebuf);

	/*
	 * Send Alert Def Update event to all Madhava's or Shyama if Shyama Handled
	 */
	if (ahdlr != AHDLR_SHYAMA) { 
		size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + sizeof(SM_ALERT_ADEF_UPD);

		auto				puniq = make_refcnt_uniq(fixed_sz);
		void				*palloc = puniq.get();

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(palloc);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
		auto				*pstat = reinterpret_cast<SM_ALERT_ADEF_UPD *>(pnot + 1);

		new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, COMM_HEADER::MS_HDR_MAGIC);
		
		new (pnot) EVENT_NOTIFY(NOTIFY_SM_ALERT_ADEF_UPD, 1);
		
		new (pstat) SM_ALERT_ADEF_UPD(adefid, newstate, is_realtime, ahdlr == AHDLR_PARTHA);

		gshconnhdlr->send_all_madhava_event(std::move(puniq), fixed_sz, phdr->get_pad_len());
	}
	else {
		gshconnhdlr->pshalerthdlr_->send_alertdef_update(adefid, newstate, is_realtime);
	}	

	/*
	 * Now update the DB 
	 */
	db_update_alertdef(&adefid, 1, newstate);
}	

bool ALERTMGR::db_update_alertdef(uint32_t *pdefidarr, uint32_t ndefs, ALERT_MSG_TYPE newstate)
{
	if (!pdefidarr || !ndefs) {
		return false;
	}

	auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
	bool				bret;
	
	if (!pconn) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection for Alert Definition Update to DB\n");

		gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return false;
	}	

	STRING_BUFFER<32 * 1024>	strbuf;

	if (newstate != ALERT_ADEF_DELETE) {
		strbuf.appendfmt("update public.alertdeftbl set disabled = \'%s\'::boolean where adefid in (", newstate == ALERT_ADEF_DISABLE ? "true" : "false");
	}
	else {
		strbuf.appendfmt("delete from public.alertdeftbl where adefid in (");
	}	

	for (uint32_t i = 0; i < ndefs; ++i) {
		strbuf.appendfmt("\'%08x\',", pdefidarr[i]);
	}	

	strbuf--;

	strbuf << ");";

	bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.length());

	if (bret == false) {
		gshconnhdlr->db_stats_.nalertdef_failed_.fetch_add_relaxed(1);

		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to set Alert Definition Update to DB due to %s\n", PQerrorMessage(pconn->get()));
		return false;
	}	

	pconn->set_resp_cb(
		[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
		{
			if (is_completed) {
				if (conn.is_within_tran()) {
					conn.pqexec_blocking("Rollback Work;");
				}						
				conn.make_available();
				return true;
			}	
			
			if (true == gyres.is_error()) {
				gshconnhdlr->db_stats_.nalertdef_failed_.fetch_add_relaxed(1);

				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to set Alert Definition Update to DB due to %s\n", gyres.get_error_msg());
				return false;
			}	

			return true;
		}
	);

	return true;
}


void ALERTMGR::handle_node_inhibits_add(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery)
{
	STACK_JSON_WRITER<2048>		writer;
	STRING_BUFFER<1024>		strbuf;
	time_t				tcurr = time(nullptr);

	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Inhibits Add Command received with missing data payload");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Inhibits Command received with invalid data : data member not of JSON Object type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	STACK_JSON_WRITER<8096, 4096>	objwriter;
	const char			*pjson;
	uint32_t			szjson;

	it->value.Accept(objwriter); 

	pjson 		= objwriter.get_string();
	szjson		= objwriter.get_size();

	auto 				[errcode, inhid, pname] = add_inhibit(0, it->value, strbuf, tcurr, tcurr);

	writer.StartObject();

	writer.KeyConst("status");

	if (inhid == 0) {
		writer.StringConst("failed");
	
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(strbuf);
	}	
	else {
		writer.StringConst("ok");

		writer.KeyConst("msg");
		writer.String(strbuf);
	}	
		
	writer.EndObject();

	// Send the status
	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();
	bool				bret;

	bret = gshconnhdlr->send_query_response(connshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	
	if (inhid == 0 || !pname) {
		WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to add new Alert Inhibit from Node : %s\n", strbuf.buffer());
		return; 
	}	

	/*
	 * Now update the DB with the new def
	 */
	bret = db_insert_inhibit(inhid, pname, tcurr, pjson, szjson);

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Added new Alert Inhibit successfully\n");
}

std::tuple<ERR_CODES_E, uint32_t, const char *> ALERTMGR::add_inhibit(uint32_t inhid, GEN_JSON_VALUE & jdoc, STR_WR_BUF & strbuf, time_t tcurr, time_t tcreate, bool is_disabled) noexcept
{
	const char 		*pname = nullptr;

	try {
		if (!jdoc.IsObject()) {
			strbuf << "Invalid Alert Inhibit Add JSON : Require a JSON Object";
			return {ERR_INVALID_REQUEST, 0, nullptr};
		}	

		if (inhibitmap_.size() >= ALERT_INHIBIT::MAX_INHIBITS) {
			strbuf.appendfmt("Alert Inhibit Add received but Max Inhibit Count is already reached %lu : "
						"Cannot add new inhibits : Please delete any unused inhibits first", inhibitmap_.size());
			return {ERR_INVALID_REQUEST, 0, nullptr};
		}

		auto 			pinuniq = std::make_unique<ALERT_INHIBIT>(jdoc, inhid, tcreate, is_disabled);

		inhid 			= pinuniq->inhid_;	// As passed inhid may be 0
		pname 			= pinuniq->name_.data();

		auto 			[it, success] = inhibitmap_.try_emplace(inhid, std::move(pinuniq));
		if (!success) {
			strbuf << "Alert Inhibit name \'" << pname << "\' already exists : Please use a different name";
			return {ERR_CONFLICTS, 0, nullptr};
		}	

		strbuf << "Added new Alert Inhibit name \'" << pname << "\' successfully : Inhibit ID is ";
		strbuf.appendfmt("\'%08x\'", inhid);

		return {ERR_STATUS_OK, inhid, pname};
	}
	GY_CATCH_EXPRESSION(
		int			ecode = GY_GET_EXCEPT_CODE();

		if (ecode == 0) ecode = ERR_SERV_ERROR;
	
		strbuf << "New Alert Inhibit failed due to : " << GY_GET_EXCEPT_STRING;
		return {ERR_CODES_E(ecode), 0, nullptr};
	);
}

bool ALERTMGR::db_insert_inhibit(uint32_t inhid, const char *name, time_t tcreate, const char *pjson, uint32_t szjson)
{
	auto				timebuf = gy_localtime_iso8601_sec(tcreate);
	bool				bret;
	auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
	
	if (!pconn) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to insert new Alert Inhibit Definition to DB\n");

		gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return false;
	}	

	char				idbuf[20];
	
	snprintf(idbuf, sizeof(idbuf), "%08x", inhid);
	
	const char			*params[5] { idbuf, name, timebuf.get(), "false", pjson };

	const char			qcmd[] = "insert into public.inhibitstbl values ($1::char(8), $2::text, $3::timestamptz, $4::boolean, $5::text) "
							"on conflict(inhid) do update set inhibit = (excluded.inhibit);\n";

	bret = PQsendQueryParams(pconn->get(), qcmd, GY_ARRAY_SIZE(params), nullptr, params, nullptr, nullptr, 0);

	if (bret == false) {
		gshconnhdlr->db_stats_.nactions_failed_.fetch_add_relaxed(1);

		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to update DB with New Alert Inhibit Definition due to %s\n", PQerrorMessage(pconn->get()));
		return false;
	}	

	pconn->set_resp_cb(
		[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
		{
			if (is_completed) {
				if (conn.is_within_tran()) {
					conn.pqexec_blocking("Rollback Work;");
				}						
				conn.make_available();
				return true;
			}	
			
			if (true == gyres.is_error()) {
				gshconnhdlr->db_stats_.nactions_failed_.fetch_add_relaxed(1);

				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to update DB with New Alert Inhibit Definition due to %s\n", gyres.get_error_msg());
				return false;
			}	

			return true;
		}
	);

	return true;
}

void ALERTMGR::handle_node_inhibits_delete(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery)
{
	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Inhibit Delete Command received with missing data payload");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Inhibit Delete Command received with invalid data : data member not of JSON Object type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	const char			*pid = nullptr, *pname = nullptr;
	uint32_t			inhid = 0;
	bool				bret;
	const auto			& obj = it->value.GetObject();
	
	it = obj.FindMember("inhid");

	if (it == obj.MemberEnd()) {
		it = obj.FindMember("name");
		
		if (it == obj.MemberEnd() || (false == it->value.IsString())) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Inhibit Delete Command received with missing mandatory fields \'inhid\' or \'name\'");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}

		pname = it->value.GetString();

		inhid = get_adef_id(pname, it->value.GetStringLength());
	}	
	else if (false == it->value.IsString()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Inhibit Delete Command received with invalid data : \'inhid\' member not of JSON string type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	else {
		pid = it->value.GetString();

		bret = string_to_number(pid, inhid, nullptr, 16);
		if (!bret) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Inhibit Delete Command received with invalid data : \'inhid\' specified is invalid : not in ID string format");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}
	}

	STACK_JSON_WRITER<2048>		writer;
	ERR_CODES_E			errcode = ERR_STATUS_OK;
	char				ebuf[255];
	size_t				len;
	bool				to_update_db = false;

	writer.StartObject();

	writer.KeyConst("status");

	auto				mit = inhibitmap_.find(inhid);

	if (mit == inhibitmap_.end()) {
		errcode	= ERR_DATA_NOT_FOUND;
		len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert Inhibit %s \'%s\' not found", pid ? "ID" : "Name", pid ? pid : pname);

		writer.StringConst("failed");
	
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(ebuf, len);
	}	
	else {
		if (mit->second) {
			auto			*pdef = mit->second.get();

			len = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Deleted Alert Inhibit \'%s\'", pdef->name_.data());
			pdef->disable();
		}
		else {
			len = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Deleted Alert Inhibit");
		}	
		
		inhibitmap_.erase(mit);

		to_update_db = true;

		writer.StringConst("ok");

		writer.KeyConst("msg");
		writer.String(ebuf, len);
	}	
		
	writer.EndObject();

	// Send the status
	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();

	bret = gshconnhdlr->send_query_response(connshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	
	if (false == to_update_db) {
		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Node Alert Inhibit Delete received : %s\n", ebuf);

	/*
	 * Now update the DB 
	 */
	db_update_inhibit(inhid, true /* is_deleted */, true);
}

void ALERTMGR::handle_node_inhibits_update(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery)
{
	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Inhibit Update Command received with missing data payload");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Inhibit Update Command received with invalid data : data member not of JSON Object type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	const char			*pid = nullptr, *pname = nullptr;
	uint32_t			inhid = 0;
	bool				bret;
	const auto			& obj = it->value.GetObject();
	
	it = obj.FindMember("inhid");

	if (it == obj.MemberEnd()) {
		it = obj.FindMember("name");
		
		if (it == obj.MemberEnd() || (false == it->value.IsString())) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Inhibit Update Command received with missing mandatory fields \'inhid\' or \'name\'");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}

		pname = it->value.GetString();

		inhid = get_adef_id(pname, it->value.GetStringLength());
	}	
	else if (false == it->value.IsString()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Inhibit Update Command received with invalid data : \'inhid\' member not of JSON string type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	else {
		pid = it->value.GetString();

		bret = string_to_number(pid, inhid, nullptr, 16);
		if (!bret) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Inhibit Update Command received with invalid data : \'inhid\' specified is invalid : not in ID string format");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}
	}

	bool				disabled, to_update_db = false;

	it = obj.FindMember("disabled");

	if (it == obj.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Inhibit Update Command received with missing field \'disabled\' : Please specify \'disabled\' as true or false");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	

	if (it->value.IsBool()) {
		disabled = it->value.GetBool();
	}
	else if (it->value.IsString()) {
		const char		*pval = it->value.GetString();

		if (0 == strcmp(pval, "false")) {
			disabled = false;
		}
		else if (0 == strcmp(pval, "true")) {
			disabled = true;
		}
		else {
			goto derr;
		}	
	}	
	else {
derr :		
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Inhibit Update Command received with invalid data : \'disabled\' member not of JSON boolean type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	
	STACK_JSON_WRITER<2048>		writer;
	ERR_CODES_E			errcode = ERR_STATUS_OK;
	char				ebuf[255];
	size_t				len;

	writer.StartObject();

	writer.KeyConst("status");

	auto				mit = inhibitmap_.find(inhid);

	if (mit == inhibitmap_.end()) {
		errcode	= ERR_DATA_NOT_FOUND;
		len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert Inhibit %s \'%s\' not found", pid ? "ID" : "Name", pid ? pid : pname);

		writer.StringConst("failed");
	
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(ebuf, len);
	}	
	else {
		if (mit->second) {
			auto			*pdef = mit->second.get();

			len = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Setting Alert Inhibit \'%s\' status to %s", pdef->name_.data(), disabled ? "Disabled" : "Enabled");

			if (disabled && !pdef->is_disabled()) {
				pdef->disable();
				to_update_db = true;
			}	
			else if (!disabled && pdef->is_disabled()) {
				pdef->enable();
				to_update_db = true;
			}	
		}
		else {
			len = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Setting Alert Inhibit status to %s", disabled ? "Disabled" : "Enabled");
		}	

		writer.StringConst("ok");

		writer.KeyConst("msg");
		writer.String(ebuf, len);
	}	
		
	writer.EndObject();

	// Send the status
	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();

	bret = gshconnhdlr->send_query_response(connshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	
	if (false == to_update_db) {
		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Node Alert Inhibit Update received : %s\n", ebuf);

	/*
	 * Now update the DB 
	 */
	db_update_inhibit(inhid, false /* is_deleted */, disabled);
}	

bool ALERTMGR::db_update_inhibit(uint32_t inhid, bool is_deleted, bool is_disabled)
{
	auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
	bool				bret;
	
	if (!pconn) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection for Alert Inhibit Update to DB\n");

		gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return false;
	}	

	STRING_BUFFER<1024>		strbuf;

	if (false == is_deleted) {
		strbuf.appendfmt("update public.inhibitstbl set disabled = \'%s\'::boolean where inhid = \'%08x\';", is_disabled ? "true" : "false", inhid);
	}
	else {
		strbuf.appendfmt("delete from public.inhibitstbl where inhid = \'%08x\';", inhid);
	}	

	bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.length());

	if (bret == false) {
		gshconnhdlr->db_stats_.ninhibits_failed_.fetch_add_relaxed(1);

		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to set Alert Inhibit Update to DB due to %s\n", PQerrorMessage(pconn->get()));
		return false;
	}	

	pconn->set_resp_cb(
		[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
		{
			if (is_completed) {
				if (conn.is_within_tran()) {
					conn.pqexec_blocking("Rollback Work;");
				}						
				conn.make_available();
				return true;
			}	
			
			if (true == gyres.is_error()) {
				gshconnhdlr->db_stats_.ninhibits_failed_.fetch_add_relaxed(1);

				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to set Alert Inhibit Update to DB due to %s\n", gyres.get_error_msg());
				return false;
			}	

			return true;
		}
	);

	return true;
}


void ALERTMGR::handle_node_silences_add(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery)
{
	STACK_JSON_WRITER<2048>		writer;
	STRING_BUFFER<1024>		strbuf;
	time_t				tcurr = time(nullptr);

	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Silences Add Command received with missing data payload");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Silences Command received with invalid data : data member not of JSON Object type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	STACK_JSON_WRITER<8096, 4096>	objwriter;
	const char			*pjson;
	uint32_t			szjson;

	it->value.Accept(objwriter); 

	pjson 		= objwriter.get_string();
	szjson		= objwriter.get_size();

	auto 				[errcode, silid, pname] = add_silence(0, it->value, strbuf, tcurr, tcurr);

	writer.StartObject();

	writer.KeyConst("status");

	if (silid == 0) {
		writer.StringConst("failed");
	
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(strbuf);
	}	
	else {
		writer.StringConst("ok");

		writer.KeyConst("msg");
		writer.String(strbuf);
	}	
		
	writer.EndObject();

	// Send the status
	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();
	bool				bret;

	bret = gshconnhdlr->send_query_response(connshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	
	if (silid == 0 || pname == nullptr) {
		WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to add new Alert Silence from Node : %s\n", strbuf.buffer());
		return; 
	}	

	/*
	 * Now update the DB with the new def
	 */
	bret = db_insert_silence(silid, pname, tcurr, pjson, szjson);

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Added new Alert Silence successfully\n");
}

std::tuple<ERR_CODES_E, uint32_t, const char *> ALERTMGR::add_silence(uint32_t silid, GEN_JSON_VALUE & jdoc, STR_WR_BUF & strbuf, time_t tcurr, time_t tcreate, bool is_disabled) noexcept
{
	const char 		*pname = nullptr;

	try {
		if (!jdoc.IsObject()) {
			strbuf << "Invalid Alert Silence Add JSON : Require a JSON Object";
			return {ERR_INVALID_REQUEST, 0, nullptr};
		}	

		if (silencemap_.size() >= ALERT_SILENCE::MAX_SILENCES) {
			strbuf.appendfmt("Alert Silence Add received but Max Silence Count is already reached %lu : "
						"Cannot add new Silences : Please delete any unused Silences first", silencemap_.size());
			return {ERR_INVALID_REQUEST, 0, nullptr};
		}

		auto 			psiluniq = std::make_unique<ALERT_SILENCE>(jdoc, silid, tcreate, is_disabled);

		silid 			= psiluniq->silid_;	// As passed silid may be 0
		pname 			= psiluniq->name_.data();

		auto 			[it, success] = silencemap_.try_emplace(silid, std::move(psiluniq));
		if (!success) {
			strbuf << "Alert Silence name \'" << pname << "\' already exists : Please use a different name";
			return {ERR_CONFLICTS, 0, nullptr};
		}	

		strbuf << "Added new Alert Silence name \'" << pname << "\' successfully : Silence ID is ";
		strbuf.appendfmt("\'%08x\'", silid);

		return {ERR_STATUS_OK, silid, pname};
	}
	GY_CATCH_EXPRESSION(
		int			ecode = GY_GET_EXCEPT_CODE();

		if (ecode == 0) ecode = ERR_SERV_ERROR;
	
		strbuf << "New Alert Silence failed due to : " << GY_GET_EXCEPT_STRING;
		return {ERR_CODES_E(ecode), 0, nullptr};
	);
}

bool ALERTMGR::db_insert_silence(uint32_t silid, const char *name, time_t tcreate, const char *pjson, uint32_t szjson)
{
	auto				timebuf = gy_localtime_iso8601_sec(tcreate);
	bool				bret;
	auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
	
	if (!pconn) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to insert new Alert Silence Definition to DB\n");

		gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return false;
	}	

	char				idbuf[20];
	
	snprintf(idbuf, sizeof(idbuf), "%08x", silid);
	
	const char			*params[5] { idbuf, name, timebuf.get(), "false", pjson };

	const char			qcmd[] = "insert into public.silencestbl values ($1::char(8), $2::text, $3::timestamptz, $4::boolean, $5::text) "
							"on conflict(silid) do update set silence = (excluded.silence);\n";

	bret = PQsendQueryParams(pconn->get(), qcmd, GY_ARRAY_SIZE(params), nullptr, params, nullptr, nullptr, 0);

	if (bret == false) {
		gshconnhdlr->db_stats_.nactions_failed_.fetch_add_relaxed(1);

		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to update DB with New Alert Silence Definition due to %s\n", PQerrorMessage(pconn->get()));
		return false;
	}	

	pconn->set_resp_cb(
		[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
		{
			if (is_completed) {
				if (conn.is_within_tran()) {
					conn.pqexec_blocking("Rollback Work;");
				}						
				conn.make_available();
				return true;
			}	
			
			if (true == gyres.is_error()) {
				gshconnhdlr->db_stats_.nactions_failed_.fetch_add_relaxed(1);

				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to update DB with New Alert Silence Definition due to %s\n", gyres.get_error_msg());
				return false;
			}	

			return true;
		}
	);

	return true;
}

void ALERTMGR::handle_node_silences_delete(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery)
{
	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Silence Delete Command received with missing data payload");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Silence Delete Command received with invalid data : data member not of JSON Object type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	const char			*pid = nullptr, *pname = nullptr;
	uint32_t			silid = 0;
	bool				bret;
	const auto			& obj = it->value.GetObject();
	
	it = obj.FindMember("silid");

	if (it == obj.MemberEnd()) {
		it = obj.FindMember("name");
		
		if (it == obj.MemberEnd() || (false == it->value.IsString())) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Silence Delete Command received with missing mandatory fields \'silid\' or \'name\'");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}

		pname = it->value.GetString();

		silid = get_adef_id(pname, it->value.GetStringLength());
	}	
	else if (false == it->value.IsString()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Silence Delete Command received with invalid data : \'silid\' member not of JSON string type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	else {
		pid = it->value.GetString();

		bret = string_to_number(pid, silid, nullptr, 16);
		if (!bret) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Silence Delete Command received with invalid data : \'silid\' specified is invalid : not in ID string format");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}
	}

	bool				to_update_db = false;

	STACK_JSON_WRITER<2048>		writer;
	ERR_CODES_E			errcode = ERR_STATUS_OK;
	char				ebuf[255];
	size_t				len;

	writer.StartObject();

	writer.KeyConst("status");

	auto				mit = silencemap_.find(silid);

	if (mit == silencemap_.end()) {
		errcode	= ERR_DATA_NOT_FOUND;
		len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert Silence %s \'%s\' not found", pid ? "ID" : "Name", pid ? pid : pname);

		writer.StringConst("failed");
	
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(ebuf, len);
	}	
	else {
		if (mit->second) {
			auto			*pdef = mit->second.get();

			len = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Deleted Alert Silence \'%s\'", pdef->name_.data());
			pdef->disable();
		}
		else {
			len = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Deleted Alert Silence");
		}	
		
		silencemap_.erase(mit);

		to_update_db = true;

		writer.StringConst("ok");

		writer.KeyConst("msg");
		writer.String(ebuf, len);
	}	
		
	writer.EndObject();

	// Send the status
	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();

	bret = gshconnhdlr->send_query_response(connshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	
	if (false == to_update_db) {
		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Node Alert Silence Delete received : %s\n", ebuf);

	/*
	 * Now update the DB 
	 */
	db_update_silence(&silid, 1, true /* is_deleted */, true);
}

void ALERTMGR::handle_node_silences_update(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery)
{
	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Silence Update Command received with missing data payload");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Silence Update Command received with invalid data : data member not of JSON Object type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	const char			*pid = nullptr, *pname = nullptr;
	uint32_t			silid = 0;
	bool				bret;
	const auto			& obj = it->value.GetObject();
	
	it = obj.FindMember("silid");

	if (it == obj.MemberEnd()) {
		it = obj.FindMember("name");
		
		if (it == obj.MemberEnd() || (false == it->value.IsString())) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Silence Update Command received with missing mandatory fields \'silid\' or \'name\'");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}

		pname = it->value.GetString();

		silid = get_adef_id(pname, it->value.GetStringLength());
	}	
	else if (false == it->value.IsString()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Silence Update Command received with invalid data : \'silid\' member not of JSON string type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	else {
		pid = it->value.GetString();

		bret = string_to_number(pid, silid, nullptr, 16);
		if (!bret) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Silence Update Command received with invalid data : \'silid\' specified is invalid : not in ID string format");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}
	}

	bool				disabled, to_update_db = false;

	it = obj.FindMember("disabled");

	if (it == obj.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Silence Update Command received with missing field \'disabled\' : Please specify \'disabled\' as true or false");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	

	if (it->value.IsBool()) {
		disabled = it->value.GetBool();
	}
	else if (it->value.IsString()) {
		const char		*pval = it->value.GetString();

		if (0 == strcmp(pval, "false")) {
			disabled = false;
		}
		else if (0 == strcmp(pval, "true")) {
			disabled = true;
		}
		else {
			goto derr;
		}	
	}	
	else {
derr :		
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Silence Update Command received with invalid data : \'disabled\' member not of JSON boolean type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	
	STACK_JSON_WRITER<2048>		writer;
	ERR_CODES_E			errcode = ERR_STATUS_OK;
	char				ebuf[255];
	size_t				len;

	writer.StartObject();

	writer.KeyConst("status");

	auto				mit = silencemap_.find(silid);

	if (mit == silencemap_.end()) {
		errcode	= ERR_DATA_NOT_FOUND;
		len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert Silence %s \'%s\' not found", pid ? "ID" : "Name", pid ? pid : pname);

		writer.StringConst("failed");
	
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(ebuf, len);
	}	
	else {
		if (mit->second) {
			auto			*pdef = mit->second.get();

			len = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Setting Alert Silence \'%s\' status to %s", pdef->name_.data(), disabled ? "Disabled" : "Enabled");

			if (disabled && !pdef->is_disabled()) {
				pdef->disable();
				to_update_db = true;
			}	
			else if (!disabled && pdef->is_disabled()) {
				pdef->enable();
				to_update_db = true;
			}	
		}
		else {
			len = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Setting Alert Silence status to %s", disabled ? "Disabled" : "Enabled");
		}	

		writer.StringConst("ok");

		writer.KeyConst("msg");
		writer.String(ebuf, len);
	}	
		
	writer.EndObject();

	// Send the status
	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();

	bret = gshconnhdlr->send_query_response(connshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	
	if (false == to_update_db) {
		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Node Alert Silence Update received : %s\n", ebuf);

	/*
	 * Now update the DB 
	 */
	db_update_silence(&silid, 1, false /* is_deleted */, disabled);
}	

bool ALERTMGR::db_update_silence(uint32_t *psilidarr, uint32_t nid, bool is_deleted, bool is_disabled)
{
	auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
	bool				bret;
	
	if (!pconn) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection for Alert Silence Update to DB\n");

		gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return false;
	}	

	STRING_BUFFER<1024>		strbuf;

	if (false == is_deleted) {
		strbuf.appendfmt("update public.silencestbl set disabled = \'%s\'::boolean where silid in (", is_disabled ? "true" : "false");
	}
	else {
		strbuf << "delete from public.silencestbl where silid in (";
	}	

	for (uint32_t i = 0; i < nid; ++i) {
		strbuf.appendfmt("\'%08x\',", psilidarr[i]);
	}	

	strbuf--;

	strbuf << ");";

	bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.length());

	if (bret == false) {
		gshconnhdlr->db_stats_.nsilences_failed_.fetch_add_relaxed(1);

		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to set Alert Silence Update to DB due to %s\n", PQerrorMessage(pconn->get()));
		return false;
	}	

	pconn->set_resp_cb(
		[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
		{
			if (is_completed) {
				if (conn.is_within_tran()) {
					conn.pqexec_blocking("Rollback Work;");
				}						
				conn.make_available();
				return true;
			}	
			
			if (true == gyres.is_error()) {
				gshconnhdlr->db_stats_.nsilences_failed_.fetch_add_relaxed(1);

				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to set Alert Silence Update to DB due to %s\n", gyres.get_error_msg());
				return false;
			}	

			return true;
		}
	);

	return true;
}


void ALERTMGR::handle_node_actions_add(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery)
{
	STACK_JSON_WRITER<2048>		writer;
	STRING_BUFFER<1024>		strbuf;
	time_t				tcurr = time(nullptr);

	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Action Add Command received with missing data payload");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Action Command received with invalid data : data member not of JSON Object type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	STACK_JSON_WRITER<8096, 4096>	objwriter;
	const char			*pjson;
	uint32_t			szjson;

	it->value.Accept(objwriter); 

	pjson 		= objwriter.get_string();
	szjson		= objwriter.get_size();

	auto 				[errcode, actionid, actttype, pname] = add_action(0, it->value, strbuf, tcurr, tcurr);

	writer.StartObject();

	writer.KeyConst("status");

	if (actionid == 0) {
		writer.StringConst("failed");
	
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(strbuf);
	}	
	else {
		writer.StringConst("ok");

		writer.KeyConst("msg");
		writer.String(strbuf);
	}	
		
	writer.EndObject();

	// Send the status
	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();
	bool				bret;

	bret = gshconnhdlr->send_query_response(connshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	
	if (actionid == 0 || !pname) {
		WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to add new Alert Action from Node : %s\n", strbuf.buffer());
		return; 
	}	

	/*
	 * Now update the DB with the new def
	 */
	bret = db_insert_update_action(actionid, pname, actttype, tcurr, pjson, szjson);

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Added new Alert Action successfully\n");
}

std::tuple<ERR_CODES_E, uint32_t, AL_ACTION_E, const char *> ALERTMGR::add_action(uint32_t actionid, GEN_JSON_VALUE & jdoc, STR_WR_BUF & strbuf, time_t tcurr, time_t tcreate) noexcept
{
	const char 		*pname = nullptr;

	try {
		if (!jdoc.IsObject()) {
			strbuf << "Invalid Alert Action Add JSON : Require a JSON Object";
			return {ERR_INVALID_REQUEST, 0, ACTION_MAX, nullptr};
		}	

		if (actionmap_.size() >= ALERT_ACTION::MAX_ACTIONS) {
			strbuf.appendfmt("Alert Action Add received but Max Action Count is already reached %lu : "
						"Cannot add new actions : Please delete any unused actions first", actionmap_.size());
			return {ERR_INVALID_REQUEST, 0, ACTION_MAX, nullptr};
		}

		auto 			pactuniq = std::make_unique<ALERT_ACTION>(jdoc, actionid, tcreate);

		auto			acttype = pactuniq->acttype_;
		actionid 		= pactuniq->actionid_;	// As passed actionid may be 0
		pname 			= pactuniq->name();

		auto 			[it, success] = actionmap_.try_emplace(actionid);
		if (!success) {
			strbuf << "Alert Action name \'" << pname << "\' already exists : Please use a different name";
			return {ERR_CONFLICTS, 0, ACTION_MAX, nullptr};
		}	
		else {
			it->second 	= pactuniq.release();
		}	

		strbuf << "Added new Alert Action name \'" << pname << "\' successfully : Action ID is ";
		strbuf.appendfmt("\'%08x\'", actionid);

		return {ERR_STATUS_OK, actionid, acttype, pname};
	}
	GY_CATCH_EXPRESSION(
		int			ecode = GY_GET_EXCEPT_CODE();

		if (ecode == 0) ecode = ERR_SERV_ERROR;
	
		strbuf << "New Alert Action failed due to : " << GY_GET_EXCEPT_STRING;
		return {ERR_CODES_E(ecode), 0, ACTION_MAX, nullptr};
	);
}

bool ALERTMGR::db_insert_update_action(uint32_t actionid, const char *name, AL_ACTION_E acttype, time_t tcreate, const char *pjson, uint32_t szjson)
{
	auto				timebuf = gy_localtime_iso8601_sec(tcreate);
	bool				bret;
	auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
	
	if (!pconn) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection to insert new Alert Action Definition to DB\n");

		gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return false;
	}	

	char				idbuf[20];
	
	snprintf(idbuf, sizeof(idbuf), "%08x", actionid);
	
	auto				actpair = action_to_stringlen(acttype);

	const char			*params[5] { idbuf, name, actpair.first, timebuf.get(), pjson };

	const char			qcmd[] = "insert into public.actionstbl values ($1::char(8), $2::text, $3::text, $4::timestamptz, $5::text) "
							"on conflict(actionid) do update set action = (excluded.action);\n";

	bret = PQsendQueryParams(pconn->get(), qcmd, GY_ARRAY_SIZE(params), nullptr, params, nullptr, nullptr, 0);

	if (bret == false) {
		gshconnhdlr->db_stats_.nactions_failed_.fetch_add_relaxed(1);

		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to update DB with New Alert Action Definition due to %s\n", PQerrorMessage(pconn->get()));
		return false;
	}	

	pconn->set_resp_cb(
		[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
		{
			if (is_completed) {
				if (conn.is_within_tran()) {
					conn.pqexec_blocking("Rollback Work;");
				}						
				conn.make_available();
				return true;
			}	
			
			if (true == gyres.is_error()) {
				gshconnhdlr->db_stats_.nactions_failed_.fetch_add_relaxed(1);

				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to update DB with New Alert Action Definition due to %s\n", gyres.get_error_msg());
				return false;
			}	

			return true;
		}
	);

	return true;
}

void ALERTMGR::handle_node_actions_update(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery)
{
	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Action Update Command received with missing data payload");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Action Update Command received with invalid data : data member not of JSON Object type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	const char			*pid = nullptr, *pname = nullptr;
	uint32_t			actionid = 0;
	bool				bret;
	const auto			& obj = it->value.GetObject();
	
	it = obj.FindMember("actionid");

	if (it == obj.MemberEnd()) {
		it = obj.FindMember("name");
		
		if (it == obj.MemberEnd() || (false == it->value.IsString())) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Action Update Command received with missing mandatory fields \'actionid\' or \'name\'");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}

		pname = it->value.GetString();

		actionid = get_adef_id(pname, it->value.GetStringLength());
	}	
	else if (false == it->value.IsString()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Action Update Command received with invalid data : \'actionid\' member not of JSON string type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	else {
		pid = it->value.GetString();

		bret = string_to_number(pid, actionid, nullptr, 16);
		if (!bret) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Action Update Command received with invalid data : \'actionid\' specified is invalid : not in ID string format");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}
	}	

	time_t				tcreate = time(nullptr);
	AL_ACTION_E			acttype	= ACTION_NULL;
	bool				to_update_db = false;

	it = obj.FindMember("config");

	if (it == obj.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Action Update Command received with missing field \'config\' : Please specify new config");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	

	if (!it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Action Update Command received with invalid data : \'config\' member not of JSON Object type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	

	auto				& jval = it->value;
	
	STACK_JSON_WRITER<8096, 4096>	objwriter;
	const char			*pjson = nullptr;
	uint32_t			szjson = 0;

	STACK_JSON_WRITER<2048>		writer;
	ERR_CODES_E			errcode = ERR_STATUS_OK;
	char				ebuf[255];
	size_t				len;

	writer.StartObject();

	writer.KeyConst("status");

	auto				mit = actionmap_.find(actionid);

	if (mit == actionmap_.end()) {
err1 :		
		errcode	= ERR_DATA_NOT_FOUND;
		len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert Action %s \'%s\' not found", pid ? "ID" : "Name", pid ? pid : pname);

		writer.StringConst("failed");
	
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(ebuf, len);
	}	
	else {
		if (mit->second && false == mit->second->is_deleted()) {
			try {

				auto			*pact = mit->second.get();

				if (auto bit = obj.FindMember("acttype"); (bit != obj.MemberEnd())) {
					if (true == bit->value.IsString()) {
						acttype = string_to_action(bit->value.GetString());

						if (acttype != pact->acttype_) {
							GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Alert Action Update cannot be used to change the Action Type \'acttype\' : "
								"Please delete the Alert Action first if change of Action Type is needed");
						}	
					}
				}	

				if (auto bit = obj.FindMember("name"); (bit != obj.MemberEnd())) {
					if (true == bit->value.IsString()) {

						if (strcmp(pact->name(), bit->value.GetString())) {
							GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Alert Action Update cannot be used to change the \'name\' : "
								"Please use the Add Action API call instead of Update Action");
						}	
					}
				}	

				pact->set_new_config(jval, tcreate);

				pname = pact->name();

				objwriter.StartObject();

				objwriter.KeyConst("name");
				objwriter.String(pact->name_.data(), pact->name_.size());

				objwriter.KeyConst("acttype");
				objwriter.String(action_to_stringlen(pact->acttype_));

				objwriter.KeyConst("config");
				jval.Accept(objwriter);

				if (auto bit = obj.FindMember("send_resolved"); (bit != obj.MemberEnd())) {
					if (true == bit->value.IsBool()) {
						pact->send_resolved_ = bit->value.GetBool();
					}
				}

				objwriter.KeyConst("send_resolved");
				objwriter.Bool(pact->send_resolved_);

				objwriter.EndObject();

				pjson 		= objwriter.get_string();
				szjson		= objwriter.get_size();

				acttype 	= pact->acttype_;

				len 		= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Updating Alert Action \'%s\' with new config", pname);

				to_update_db 	= true;

				writer.StringConst("ok");

				writer.KeyConst("msg");
				writer.String(ebuf, len);
			}
			GY_CATCH_EXPRESSION(
				errcode = (ERR_CODES_E)GY_GET_EXCEPT_CODE();

				if (errcode == 0) errcode = ERR_SERV_ERROR;
			
				len = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert Action Update failed : %s", GY_GET_EXCEPT_STRING);

				writer.StringConst("failed");
			
				writer.KeyConst("error");
				writer.Uint(errcode);

				writer.KeyConst("errmsg");
				writer.String(ebuf, len);
			);
		}
		else {
			goto err1;
		}	
	}	
		
	writer.EndObject();

	// Send the status
	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();

	bret = gshconnhdlr->send_query_response(connshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	
	if (false == to_update_db || !pname || !pjson) {
		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Node Alert Action Update received : %s\n", ebuf);

	/*
	 * Now update the DB 
	 */
	db_insert_update_action(actionid, pname, acttype, tcreate, pjson, szjson);
}

void ALERTMGR::handle_node_actions_delete(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, GEN_JSON_VALUE & jdoc, comm::QUERY_CMD *pquery)
{
	auto				it = jdoc.FindMember("data");
	
	if (it == jdoc.MemberEnd()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Action Delete Command received with missing data payload");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}
	else if (false == it->value.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Action Delete Command received with invalid data : data member not of JSON Object type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	const char			*pid = nullptr, *pname = nullptr;
	uint32_t			actionid = 0;
	bool				bret;
	const auto			& obj = it->value.GetObject();
	
	it = obj.FindMember("actionid");

	if (it == obj.MemberEnd()) {
		it = obj.FindMember("name");
		
		if (it == obj.MemberEnd() || (false == it->value.IsString())) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Action Delete Command received with missing mandatory fields \'actionid\' or \'name\'");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}

		pname = it->value.GetString();

		actionid = get_adef_id(pname, it->value.GetStringLength());
	}	
	else if (false == it->value.IsString()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Action Delete Command received with invalid data : \'actionid\' member not of JSON string type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	else {
		pid = it->value.GetString();

		bret = string_to_number(pid, actionid, nullptr, 16);
		if (!bret) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Action Delete Command received with invalid data : \'actionid\' specified is invalid : not in ID string format");

			gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
			return;
		}
	}

	bool				to_update_db = false;

	STACK_JSON_WRITER<2048>		writer;
	ERR_CODES_E			errcode = ERR_STATUS_OK;
	char				ebuf[255];
	size_t				len;

	writer.StartObject();

	writer.KeyConst("status");

	auto				mit = actionmap_.find(actionid);

	if (mit == actionmap_.end()) {
		errcode	= ERR_DATA_NOT_FOUND;
		len 	= GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert Action %s \'%s\' not found", pid ? "ID" : "Name", pid ? pid : pname);

		writer.StringConst("failed");
	
		writer.KeyConst("error");
		writer.Uint(errcode);

		writer.KeyConst("errmsg");
		writer.String(ebuf, len);
	}	
	else {
		if (mit->second) {
			auto			*pdef = mit->second.get();

			len = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Deleted Alert Action \'%s\'", pdef->name());
			pdef->set_deleted();
		}
		else {
			len = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Deleted Alert Action");
		}	
		
		actionmap_.erase(mit);

		to_update_db = true;

		writer.StringConst("ok");

		writer.KeyConst("msg");
		writer.String(ebuf, len);
	}	
		
	writer.EndObject();

	// Send the status
	const char			*pstr = writer.get_string();
	uint32_t			lenstr = writer.get_size();

	bret = gshconnhdlr->send_query_response(connshr, pquery->get_seqid(), RESP_WEB_JSON, errcode, RESP_JSON_WITH_HEADER, pstr, lenstr);
	
	if (false == to_update_db) {
		return;
	}	

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Node Alert Action Delete received : %s\n", ebuf);

	/*
	 * Now update the DB 
	 */
	db_delete_action(actionid);
}

bool ALERTMGR::db_delete_action(uint32_t actionid)
{
	auto				pconn = dbmgrpool_.get_conn(true /* wait_response_if_unavail */, 30'000 /* max_msec_wait */, true /* reset_on_timeout */);
	bool				bret;
	
	if (!pconn) {
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to get a connection for Alert Action Delete to DB\n");

		gshconnhdlr->db_stats_.nconns_failed_.fetch_add_relaxed(1);
		gshconnhdlr->db_stats_.ndbquery_failed_.fetch_add_relaxed(1);

		return false;
	}	

	STRING_BUFFER<1024>		strbuf;

	strbuf.appendfmt("delete from public.actionstbl where actionid = \'%08x\';", actionid);

	bret = PQsendQueryOptim(pconn->get(), strbuf.buffer(), strbuf.length());

	if (bret == false) {
		gshconnhdlr->db_stats_.nactions_failed_.fetch_add_relaxed(1);

		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to set Alert Action Delete to DB due to %s\n", PQerrorMessage(pconn->get()));
		return false;
	}	

	pconn->set_resp_cb(
		[this](GyPGConn & conn, GyPGresult gyres, bool is_completed) -> bool
		{
			if (is_completed) {
				if (conn.is_within_tran()) {
					conn.pqexec_blocking("Rollback Work;");
				}						
				conn.make_available();
				return true;
			}	
			
			if (true == gyres.is_error()) {
				gshconnhdlr->db_stats_.nactions_failed_.fetch_add_relaxed(1);

				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to set Alert Action Delete to DB due to %s\n", gyres.get_error_msg());
				return false;
			}	

			return true;
		}
	);

	return true;
}


void ALERTMGR::handle_crud_cmd(const std::shared_ptr<SHCONN_HANDLER::SHCONNTRACK> & connshr, comm::QUERY_CMD *pquery, char *pjson, char *pendptr)
{
	time_t				tcurr = time(nullptr);
	uint64_t			resp_seqid = pquery->get_seqid();

	if (gy_unlikely(pquery->is_expired(tcurr))) {
		WARNPRINTCOLOR_OFFLOAD(GY_COLOR_LIGHT_RED, "Node Alert Command received but Command already expired before starting processing...\n");
		
		gshconnhdlr->send_json_error_resp(connshr, ERR_TIMED_OUT, pquery->get_seqid(), "Command already timed out before starting processing");
		return;
	}

	if (pjson + MAX_QUERY_STRLEN < pendptr) {
		auto 			sarr = gy_to_strarray<256>("Max Command Length %lu exceeded : Please reduce the command size", MAX_QUERY_STRLEN);

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), sarr.get(), sarr.size());
		return;
	}	

	JSON_DOCUMENT<16 * 1024, 8192>	doc;
	auto				& jdoc = doc.get_doc();

	if (pjson + 1 >= pendptr) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Invalid Node Alert Command JSON : Empty command seen");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	if (pendptr > pjson && *(pendptr - 1) == 0) {
		pendptr--;
		jdoc.ParseInsitu(pjson);	
	}
	else {
		jdoc.Parse(pjson, pendptr - pjson);
	}

	if (jdoc.HasParseError()) {
		char			ebuf[256];
		const char		*perrorstr = rapidjson::GetParseError_En(jdoc.GetParseError());

		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Invalid Node Alert Command JSON : Error at offset %lu : Error is \'%s\'\n\n", 
			jdoc.GetErrorOffset(), perrorstr);

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Invalid Node Alert Command JSON : Error is %s", perrorstr);

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	

	if (false == jdoc.IsObject()) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Invalid Node Alert Command JSON : Need a JSON Object but command not of Object type");

		gshconnhdlr->send_json_error_resp(connshr, ERR_INVALID_REQUEST, pquery->get_seqid(), ebuf, lenerr);
		return;
	}	
	
	auto			mtype = gy_get_json_mtype(jdoc);
		
	if (!((mtype == NODE_MSG_ADD) || (mtype == NODE_MSG_UPDATE) || (mtype == NODE_MSG_DELETE))) {
		char			ebuf[256];

		auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Command received with invalid / not handled Msg Type %d", mtype);

		gshconnhdlr->send_json_error_resp(connshr, ERR_SERV_ERROR, pquery->get_seqid(), ebuf, lenerr);
		return;
	}

	auto 			qtype = gy_get_json_qtype(jdoc);

	switch (qtype) {
	
	case NQUERY_NS_ALERTS :	
		if (mtype == NODE_MSG_UPDATE) {
			handle_node_alert_stat_update(connshr, jdoc, pquery, tcurr);
		}
		else {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Command received with invalid Msg Type %d : Only Alert Updates allowed", mtype);

			gshconnhdlr->send_json_error_resp(connshr, ERR_SERV_ERROR, pquery->get_seqid(), ebuf, lenerr);
			return;
		}	
		break;
	
	case NQUERY_NS_ALERTDEF :
		if (mtype == NODE_MSG_ADD) {
			handle_node_alertdef_add(connshr, jdoc, jdoc.GetAllocator(), pquery);
		}
		else if (mtype == NODE_MSG_DELETE) {
			handle_node_alertdef_delete(connshr, jdoc, pquery);
		}
		else {
			handle_node_alertdef_update(connshr, jdoc, pquery);
		}	
		break;

	case NQUERY_NS_INHIBITS :
		if (mtype == NODE_MSG_ADD) {
			handle_node_inhibits_add(connshr, jdoc, pquery);
		}
		else if (mtype == NODE_MSG_DELETE) {
			handle_node_inhibits_delete(connshr, jdoc, pquery);
		}
		else {
			handle_node_inhibits_update(connshr, jdoc, pquery);
		}	
		break;


	case NQUERY_NS_SILENCES :
		if (mtype == NODE_MSG_ADD) {
			handle_node_silences_add(connshr, jdoc, pquery);
		}
		else if (mtype == NODE_MSG_DELETE) {
			handle_node_silences_delete(connshr, jdoc, pquery);
		}
		else {
			handle_node_silences_update(connshr, jdoc, pquery);
		}	
		break;

	case NQUERY_NS_ACTIONS :
		if (mtype == NODE_MSG_ADD) {
			handle_node_actions_add(connshr, jdoc, pquery);
		}
		else if (mtype == NODE_MSG_DELETE) {
			handle_node_actions_delete(connshr, jdoc, pquery);
		}
		else {
			handle_node_actions_update(connshr, jdoc, pquery);
		}	
		break;

	default :			
		if (true) {
			char			ebuf[256];

			auto lenerr = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Node Alert Command received with invalid Query Type %d", qtype);

			gshconnhdlr->send_json_error_resp(connshr, ERR_SERV_ERROR, pquery->get_seqid(), ebuf, lenerr);
		}
		return;
	}	
}	

bool ALERTMGR::send_shyama_all_alertdefs() noexcept
{
	try {
		time_t				tcurr = time(nullptr);
		int				ndefs = 0;

		for (const auto & [adefid, pdefint] : adefmap_) {
			if (!pdefint || pdefint->is_deleted() || !pdefint->defstr_.size() || !pdefint->is_shyama_handled()) {
				continue;
			}	

			uint32_t		szjson = pdefint->defstr_.size();
			
			gshconnhdlr->pshalerthdlr_->send_new_alertdef(tcurr, pdefint->defstr_.data(), szjson + 1, pdefint->adef_id_, pdefint->asubsys_, pdefint->isrealtime_);
			
			ndefs++;
		}

		if (ndefs > 0) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Sent %d Shyama Handled Alertdefs to Shyama Alert Handler\n", ndefs);
		}	

		return true;
	}
	GY_CATCH_EXPRESSION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to send Shyama All Alert Definitions due to exception : %s\n", GY_GET_EXCEPT_STRING);
		return false;
	)
}	


void ALERTMGR::check_adef_status() noexcept
{
	try {
		struct tm			tmstart = {};
		time_t				tcurr = time(nullptr), tstart = tcurr, tend = gy_align_up(tstart + 1, 60); 

		localtime_r(&tstart, &tmstart);
		
		static_assert(MAX_ALERT_DEFS < 2048);

		uint32_t			adelidarr[MAX_ALERT_DEFS], niddel = 0, npings = 0;
		uint32_t			aupdidarr[MAX_ALERT_DEFS], nidupd = 0;

		alignas(8) uint8_t		defbuf[sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + MAX_ALERT_DEFS * sizeof(SM_ALERT_ADEF_UPD) + 64], *pendbuf;

		static_assert(sizeof(defbuf) < 128 * 1024, "Please change the logic for this function");

		pendbuf 			= defbuf + sizeof(defbuf) - sizeof(SM_ALERT_ADEF_UPD);

		COMM_HEADER			*phdr = reinterpret_cast<COMM_HEADER *>(defbuf);
		EVENT_NOTIFY			*pnot = reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 
		auto				*pupd = reinterpret_cast<SM_ALERT_ADEF_UPD *>(pnot + 1);

		SM_ALERT_ADEF_UPD		*pstartupd = pupd, *ptmp = pupd;
		const bool			pingall = (tcurr >= tnextdefping_);

		for (auto it = adefmap_.begin(), nextit = it; it != adefmap_.end() && (uint8_t *)ptmp < pendbuf; it = nextit) {
			
			++nextit;

			uint32_t		adefid = it->first;
			auto			& pdefint = it->second;

			if (!pdefint || pdefint->is_deleted()) {
				adefmap_.erase(it);
				continue;
			}	
			
			auto			*pdef = pdefint.get();
			bool			pingsent = false;

			if (pdef->tend_sec_ <= tcurr) {
				pingsent = true;
				npings++;

				if (false == pdef->is_shyama_handled()) {
					new (ptmp++) SM_ALERT_ADEF_UPD(adefid, ALERT_ADEF_DELETE, pdef->isrealtime_, pdef->is_partha_handled());
				}
				else {
					gshconnhdlr->pshalerthdlr_->send_alertdef_update(adefid, ALERT_ADEF_DELETE, pdef->isrealtime_);
				}	

				INFOPRINTCOLOR_OFFLOAD(GY_COLOR_CYAN, "Deleting Alert Definition for \'%s\' as End Time (endsat) has been reached\n", pdef->name());

				adelidarr[niddel++] = adefid;

				pdef->set_deleted();
				adefmap_.erase(it);

				continue;
			}	
			else if (pdef->state_.load(mo_relaxed) == ADEFSTATE_DISABLED && pdef->tstart_sec_ + 120 > tcurr && pdef->tstart_sec_ <= tcurr && pdef->tstart_sec_ > pdef->tinit_) {
				pingsent = true;
				npings++;

				pdef->set_state(ADEFSTATE_ENABLED);

				if (false == pdef->is_shyama_handled()) {
					new (ptmp++) SM_ALERT_ADEF_UPD(adefid, ALERT_ADEF_ENABLE, pdef->isrealtime_, pdef->is_partha_handled());
				}
				else {
					gshconnhdlr->pshalerthdlr_->send_alertdef_update(adefid, ALERT_ADEF_ENABLE, pdef->isrealtime_);
				}	

				aupdidarr[nidupd++] = adefid;
			}	

			if (pdef->pmute_) {
				if (true == pdef->pmute_->in_range(tmstart, tstart)) {
					if (pdef->is_enabled()) {
						pdef->set_state(ADEFSTATE_MUTED);

						if (tend > tstart + 10) {
							pingsent = true;
							npings++;

							if (false == pdef->is_shyama_handled()) {
								new (ptmp++) SM_ALERT_ADEF_UPD(adefid, ALERT_ADEF_MUTE, pdef->isrealtime_, pdef->is_partha_handled());
							}
							else {
								gshconnhdlr->pshalerthdlr_->send_alertdef_update(adefid, ALERT_ADEF_MUTE, pdef->isrealtime_);
							}	
						}	
					}
				}	
				else if (ADEFSTATE_MUTED == pdef->state_.load(mo_relaxed)) {
					pingsent = true;
					npings++;

					pdef->set_state(ADEFSTATE_ENABLED);

					if (false == pdef->is_shyama_handled()) {
						new (ptmp++) SM_ALERT_ADEF_UPD(adefid, ALERT_ADEF_ENABLE, pdef->isrealtime_, pdef->is_partha_handled());
					}
					else {
						gshconnhdlr->pshalerthdlr_->send_alertdef_update(adefid, ALERT_ADEF_ENABLE, pdef->isrealtime_);
					}
				}	
			}

			pdef->check_actions();

			if (pingall && false == pingsent) {
				pingsent = true;
				npings++;

				ALERT_MSG_TYPE			type = pdef->state_.load(mo_relaxed) == ADEFSTATE_DISABLED ? ALERT_ADEF_DISABLE : ALERT_ADEF_ENABLE;

				if (false == pdef->is_shyama_handled()) {
					new (ptmp++) SM_ALERT_ADEF_UPD(adefid, type, pdef->isrealtime_, pdef->is_partha_handled());
				}
				else {
					gshconnhdlr->pshalerthdlr_->send_alertdef_update(adefid, type, pdef->isrealtime_);
				}	
			}
		}

		if (npings == 0) {
			return;
		}	
		
		int				nupd = ptmp - pupd;

		if (nupd > 0) {

			size_t				fixed_sz = sizeof(COMM_HEADER) + sizeof(EVENT_NOTIFY) + nupd * sizeof(SM_ALERT_ADEF_UPD);

			auto				puniq = make_refcnt_uniq(fixed_sz);
			void				*palloc = puniq.get();

			phdr 				= reinterpret_cast<COMM_HEADER *>(palloc);
			pnot 				= reinterpret_cast<EVENT_NOTIFY *>(phdr + 1); 

			auto				*pstat = reinterpret_cast<SM_ALERT_ADEF_UPD *>(pnot + 1);

			new (phdr) COMM_HEADER(COMM_EVENT_NOTIFY, fixed_sz, COMM_HEADER::MS_HDR_MAGIC);
			
			new (pnot) EVENT_NOTIFY(NOTIFY_SM_ALERT_ADEF_UPD, nupd);
			
			for (int i = 0; i < nupd; ++i) {
				new (pstat++) SM_ALERT_ADEF_UPD(*pupd++);
			}	

			gshconnhdlr->send_all_madhava_event(std::move(puniq), fixed_sz, phdr->get_pad_len());
			
		}

		if (pingall) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Sent %d Alert Definition Pings to all Madhavas and %d Pings to local Shyama\n", nupd, npings - nupd);

			tnextdefping_ = time(nullptr) + 600;
		}

		/*
		 * Now update the DB for the deleted defs
		 */
		if (niddel > 0) { 
			db_update_alertdef(adelidarr, niddel, ALERT_ADEF_DELETE);
		}

		if (nidupd > 0) { 
			db_update_alertdef(aupdidarr, nidupd, ALERT_ADEF_ENABLE);
		}
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking if Alertmgr Alert Definition Status : %s\n", GY_GET_EXCEPT_STRING);
	);
}	

void ALERTMGR::check_silences_active() noexcept
{
	try {
		uint32_t			delidarr[ALERT_SILENCE::MAX_SILENCES], ndel = 0;
		struct tm			tmstart = {};
		bool				is_muted = false;
		time_t				tcurr = time(nullptr), tstart = gy_align_up(tcurr, 60), tend; 

		localtime_r(&tstart, &tmstart);
		
		for (auto it = silencemap_.begin(), nextit = it; it != silencemap_.end(); it = nextit) {
			
			++nextit;

			uint32_t		silid = it->first;
			auto			& psilence = it->second;

			if (!psilence) {
				continue;
			}	

			if (psilence->tend_sec_ <= tcurr) {
				delidarr[ndel++] = silid;
				silencemap_.erase(it);
				
				continue;
			}

			if (true == psilence->is_disabled()) {
				continue;
			}	
			
			if (true == psilence->mutetimes_.in_range(tmstart, tstart)) {
				is_muted = true;
			}	
		}

		if (is_muted) {
			tany_silence_end_ = tstart + 59;
		}	

		if (ndel > 0) {
			INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "Deleting %u Alert Silence Definitions due to expiry...\n", ndel);

			db_update_silence(delidarr, ndel, true /* is_deleted */, false /* is_disabled */);
		}	
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking if silences active in Alertmgr : %s\n", GY_GET_EXCEPT_STRING);
	);
}	

void ALERTMGR::check_alert_stats() noexcept
{
	ALERT_STATS			*pastat;
	time_t				tcurr = time(nullptr), texpire = tcurr - 180, tleast = tcurr;
	int				nclose = 0, nexp = 0, ndefdel = 0;

	for (auto it = astatmap_.begin(), nextit = it; it != astatmap_.end(); it = nextit) {
		try {
			nextit++;

			pastat = it->second.get();

			if (!pastat || pastat->is_deleted()) {
				astatmap_.erase(it);
				nclose++;
				continue;
			}
			
			if ((pastat->tforce_close_ < texpire) || (pastat->pdef_ && pastat->pdef_->is_deleted())) {

				cleanup_alert_stat(pastat->get_alertid(), *pastat, tcurr, true /* is_close */, true /* is_force_close */);
				nclose++;

				if (pastat->tforce_close_ < texpire) {
					nexp++;
				}
				else {
					ndefdel++;
				}	

				astatmap_.erase(it);
				
				continue;
			}

			if (pastat->tstart_ < tleast) {
				tleast = pastat->tstart_;
			}	
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1,
				ERRORPRINT_OFFLOAD("Exception occurred while Checking Alert Stats in Alertmgr : %s\n", GY_GET_EXCEPT_STRING);
			)
		);
	}
	
	tleastalert_ = std::max<time_t>(tcurr - MAX_ALERT_FORCE_CLOSE_SEC - 600, tleast);

	if (nclose > 0) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Closed %d Alerts Stats with %d by Time Expiry and %d by Definition Deletes\n", nclose, nexp, ndefdel);
	}
}

void ALERTMGR::check_agroup_status() noexcept
{
	ALERT_GROUP			*pgroup;
	uint64_t			currtusec = get_usec_time(), exptusec = currtusec - 5 * GY_USEC_PER_MINUTE;
	int				nclose = 0, nexp = 0;

	for (auto it = agroupmap_.begin(), nextit = it; it != agroupmap_.end(); it = nextit) {
		try {
			nextit++;

			pgroup = it->second.get();

			if (!pgroup || pgroup->is_deleted()) {
				agroupmap_.erase(it);
				nclose++;
				continue;
			}
			
			if (pgroup->tnextchkusec_ < exptusec) {

				agroup_send_alerts(*pgroup);

				erase_group_timemap(pgroup, pgroup->tnextchkusec_);

				nclose++;
				nexp++;

				continue;
			}
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1,
				ERRORPRINT_OFFLOAD("Exception occurred while Checking Alert Groups in Alertmgr : %s\n", GY_GET_EXCEPT_STRING);
			)
		);
	}
	
	if (nclose > 0) {
		INFOPRINTCOLOR_OFFLOAD(GY_COLOR_GREEN, "Closed %d Alerts Groups with %d by Time Expiry\n", nclose, nexp);
	}
}

void ALERTMGR::update_alert_stats() 
{
	STRING_BUFFER<2048>		strbuf;
	auto				& roll = *rollstats_.get();
	time_t				tcurr = time(nullptr);
	int64_t				tsec = tcurr - roll.tlastprint_;

	roll.acc_alerts_(nalerts_ - roll.lastnalerts_);
	roll.acc_silenced_(nalerts_silenced_ - roll.lastnalerts_silenced_);
	roll.acc_inhib_(nalerts_inhib_ - roll.lastnalerts_inhib_);

	roll.day_alerts_		= rolling_sum(roll.acc_alerts_);	
	roll.day_silenced_		= rolling_sum(roll.acc_silenced_);	
	roll.day_inhib_			= rolling_sum(roll.acc_inhib_);	

	strbuf << "Alertmgr Stats for the last " << tsec << " secs : " 
		<< nalerts_ - roll.lastnalerts_ << " New Alerts, "  << ninvalid_alerts_ - roll.lastninvalid_alerts_ << " Invalid Alerts, "
		<< nalerts_skipped_ - roll.lastnalerts_skipped_ << " Skipped Alerts, " 
		<< nalerts_silenced_ - roll.lastnalerts_silenced_ << " Alerts Skipped by Silencing, "
		<< nalerts_inhib_ - roll.lastnalerts_inhib_ << " Alerts Skipped by Inhibition"
		
		<< "\n\t\t\t24 hours Alert Stats : " << roll.day_alerts_ << " Alerts, " << roll.day_silenced_ << " Alerts Silenced, " << roll.day_inhib_ << " Alerts Inhibited"

		<< "\n\t\t\tCumulative Alert Stats : " << nalerts_ << " Total Alerts, " << ninvalid_alerts_ << " Invalid Alerts, "
		<< nalerts_skipped_ << " Skipped Alerts, " << nalerts_silenced_ << " Alerts Skipped by Silencing, "
		<< nalerts_inhib_ << " Alerts Skipped by Inhibition"
	
		<< "\n\t\t\tAlerts seen : " << nalerts_min_ << " in last minute, " << nalerts_hour_ << " in last hour"

		<< "\n\n\t\t\tOther Stats : " << adefmap_.size() << " Total Alert Definitions, " 
		<< inhibitmap_.size() << " Total Inhibit Defs, " <<  silencemap_.size() << " Total Silences, "
		<< actionmap_.size() << " Total Action Defs, " << agroupmap_.size() << " Total Alert Groups active, "
		<< astatmap_.size() << " Total Alert Stats active, " << atimemap_.size() << " Timemap Entries";

	INFOPRINTCOLOR_OFFLOAD(GY_COLOR_BLUE, "%s\n\n", strbuf.buffer());

	roll.tlastprint_			= tcurr;

	roll.lastnalerts_			= nalerts_;
	roll.lastninvalid_alerts_		= ninvalid_alerts_;
	roll.lastnalerts_skipped_		= nalerts_skipped_;
	roll.lastnalerts_silenced_		= nalerts_silenced_;
	roll.lastnalerts_inhib_			= nalerts_inhib_;
}	

// Called from another thread
std::tuple<uint32_t, uint32_t, uint32_t> ALERTMGR::get_alert_day_stats() const noexcept
{
	const auto			& roll = *rollstats_.get();

	return {
		GY_READ_ONCE(roll.day_alerts_) 		+ GY_READ_ONCE(nalerts_) - GY_READ_ONCE(roll.lastnalerts_),
		GY_READ_ONCE(roll.day_silenced_) 	+ GY_READ_ONCE(nalerts_silenced_) - GY_READ_ONCE(roll.lastnalerts_silenced_),
		GY_READ_ONCE(roll.day_inhib_) 		+ GY_READ_ONCE(nalerts_inhib_) - GY_READ_ONCE(roll.lastnalerts_inhib_)
	};
}

void ALERTMGR::check_schedules(time_t & tnext) noexcept
{
	try {
		uint64_t			currusec = get_usec_time(), maxusec = currusec + GY_USEC_PER_SEC - GY_USEC_PER_MSEC, tusec = 0;
		time_t				tcurr = currusec/GY_USEC_PER_SEC;
		size_t				nchecks = 0;

		tnext = tcurr + 1;
		
		/*
		 * NOTE : If atimemap_ multi element erase happens we need to restart the scan to avoid
		 * referencing an invalid iterator. Please avoid directly erasing elements from atimemap_. Use
		 * the erase_group_timemap() and such methods which set the multierase_ flag
		 */
		multierase_ = false;

		for (auto it = atimemap_.begin(), nextit = it; it != atimemap_.end(); it = (!multierase_ ? nextit : ({ multierase_ = false; atimemap_.upper_bound(tusec > 0 ? tusec - 1 : 0); }) )) {

			++nextit;
	
			tusec 			= GY_READ_ONCE(it->first);

			CmdParam		& param = it->second;

			if (tusec > maxusec) {
				tnext = tusec/GY_USEC_PER_SEC + 1;
				return;
			}	

			if (++nchecks > MAX_TOTAL_ALERTS_PER_HOUR * 10) {
				return;
			}

			try {
				switch (param.cmd_) {
					
				case ACmd::CmdGroupSendAlerts	:
					
					if (param.pgroup_ && !param.pgroup_->is_deleted()) {
						CmdParam		pold = std::move(param);
						
						agroup_send_alerts(*pold.pgroup_.get());
					}	

					atimemap_.erase(it);
					break;

				case ACmd::CmdCheckADef :
					
					if (true) {
						check_adef_status();

						auto			mnode = atimemap_.extract(it);
						uint32_t		repeat_sec = param.repeat_sec_ > 0 ? param.repeat_sec_ : 60;

						if (bool(mnode)) {

							mnode.key() = gy_align_up(time(nullptr) + 1, repeat_sec) * GY_USEC_PER_SEC + 100'000;
							atimemap_.insert(std::move(mnode));
						}
					}
					break;

				case ACmd::CmdCheckSilence :
					
					if (true) {
						check_silences_active();

						auto			mnode = atimemap_.extract(it);
						uint32_t		repeat_sec = param.repeat_sec_ > 0 ? param.repeat_sec_ : 60;

						if (bool(mnode)) {

							mnode.key() = (gy_align_up(time(nullptr) + 1, repeat_sec) - 2) * GY_USEC_PER_SEC + 10000;
							atimemap_.insert(std::move(mnode));
						}
					}
					break;

				case ACmd::CmdConnReset :
					
					if (true) {
						
						dbmgrpool_.reset_idle_conns();
						
						auto			mnode = atimemap_.extract(it);
						uint32_t		repeat_sec = param.repeat_sec_ > 0 ? param.repeat_sec_ : 700;

						if (bool(mnode)) {
							mnode.key() = gy_align_up(time(nullptr) + 1, repeat_sec) * GY_USEC_PER_SEC + 400'000;
							atimemap_.insert(std::move(mnode));
						}
					}
					break;

				case ACmd::CmdAlertStatCheck :
					
					if (true) {
						check_alert_stats();

						auto			mnode = atimemap_.extract(it);
						uint32_t		repeat_sec = param.repeat_sec_ > 0 ? param.repeat_sec_ : 600;

						if (bool(mnode)) {

							mnode.key() = gy_align_up(time(nullptr) + 1, repeat_sec) * GY_USEC_PER_SEC + 200'000;
							atimemap_.insert(std::move(mnode));
						}
					}
					break;

				case ACmd::CmdAlertGroupCheck :
					
					if (true) {
						check_agroup_status();

						auto			mnode = atimemap_.extract(it);
						uint32_t		repeat_sec = param.repeat_sec_ > 0 ? param.repeat_sec_ : 400;

						if (bool(mnode)) {

							mnode.key() = gy_align_up(time(nullptr) + 1, repeat_sec) * GY_USEC_PER_SEC + 300'000;
							atimemap_.insert(std::move(mnode));
						}
					}
					break;

				case ACmd::CmdAlertStats :
					
					if (true) {
						update_alert_stats();

						auto			mnode = atimemap_.extract(it);
						uint32_t		repeat_sec = param.repeat_sec_ > 0 ? param.repeat_sec_ : 300;

						if (bool(mnode)) {

							mnode.key() = gy_align_up(time(nullptr) + 1, repeat_sec) * GY_USEC_PER_SEC + 500'000;
							atimemap_.insert(std::move(mnode));
						}
					}
					break;


				default :
					atimemap_.erase(it);
					break;
				}
			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking an Alertmgr scheduled task (%d) : %s\n", (int)param.cmd_, GY_GET_EXCEPT_STRING);
			);
		}
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught while checking Alertmgr scheduled tasks : %s\n", GY_GET_EXCEPT_STRING);
	);
}


ALERTMGR::ALERTMGR(SA_SETTINGS_C & settings, SHCONN_HANDLER *pconnhdlr)
	: 
	cusec_init_(({
			galertmgr 	= this;
			gshconnhdlr	= pconnhdlr;
			gsettings	= &settings,
			get_usec_clock();
			})),
	dbmgrpool_("Alertmgr DB Pool", NUM_DB_CONNS, settings.postgres_hostname, settings.postgres_port, settings.postgres_user, settings.postgres_password, pconnhdlr->get_dbname().get(),
				"dbalertmgr", get_db_init_commands().get(), true /* auto_reconnect */, 12, 10, 10),
	rollstats_(std::make_unique<AlertRollStats>(tinit_)),
	dbhdlr_(settings.postgres_hostname, settings.postgres_port, settings.postgres_user, settings.postgres_password, pconnhdlr->get_dbname().get()),
	act_thr_("Alert Action Thread", GET_PTHREAD_WRAPPER(alert_act_thread), this, nullptr, nullptr, true,
		2 * 1024 * 1024 /* Stack */, 2000, true, true, true /* thr_func_calls_init_done */, 5000, true),
	db_thr_("Alert DB Thread", GET_PTHREAD_WRAPPER(alert_db_thread), this, nullptr, nullptr, true,
		2 * 1024 * 1024 /* Stack */, 2000, true, true, true /* thr_func_calls_init_done */, 5000, true)
{
	time_t			tcurr = time(nullptr);
	uint64_t		tusec;

	act_thr_.clear_cond();
	db_thr_.clear_cond();

	/*
	 * Add Schedules
	 */
	tusec = (gy_align_down(tcurr, 60) + 120 - 2) * GY_USEC_PER_SEC + 10000;
	atimemap_.emplace(std::piecewise_construct, std::forward_as_tuple(tusec), std::forward_as_tuple(ACmd::CmdCheckSilence, 60)); 

	tusec = (gy_align_up(tcurr + 1, 60)) * GY_USEC_PER_SEC + 100'000;
	atimemap_.emplace(std::piecewise_construct, std::forward_as_tuple(tusec), std::forward_as_tuple(ACmd::CmdCheckADef, 60)); 

	tusec = (gy_align_up(tcurr + 1, 300)) * GY_USEC_PER_SEC + 500'000;
	atimemap_.emplace(std::piecewise_construct, std::forward_as_tuple(tusec), std::forward_as_tuple(ACmd::CmdAlertStats, 300)); 

	tusec = (gy_align_up(tcurr + 1, 600)) * GY_USEC_PER_SEC + 200'000;
	atimemap_.emplace(std::piecewise_construct, std::forward_as_tuple(tusec), std::forward_as_tuple(ACmd::CmdAlertStatCheck, 600)); 

	tusec = (gy_align_up(tcurr + 1, 400)) * GY_USEC_PER_SEC + 300'000;
	atimemap_.emplace(std::piecewise_construct, std::forward_as_tuple(tusec), std::forward_as_tuple(ACmd::CmdAlertGroupCheck, 400)); 

	tusec = (gy_align_up(tcurr + 1, 700)) * GY_USEC_PER_SEC + 400'000;
	atimemap_.emplace(std::piecewise_construct, std::forward_as_tuple(tusec), std::forward_as_tuple(ACmd::CmdConnReset, 700)); 

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Initialized Alert Manager successfully...\n");
}	
	
ALERTMGR * ALERTMGR::get_singleton() noexcept
{
	return galertmgr;
}	

bool SHCONN_HANDLER::send_madhava_all_alertdefs(MADHAVA_INFO *pmad, const std::shared_ptr<SHCONNTRACK> & connshr) noexcept
{
	try {
		SHSTREAM_EVENT_BUF		streambuf(connshr, *this, NOTIFY_SM_ALERT_ADEF_NEW, SM_ALERT_ADEF_NEW::MAX_NUM_DEFS);

		if (palertmgr_->adefmap_.size() > 8) {
			// Preallocate memory
			streambuf.get_buf(std::min<uint32_t>(palertmgr_->adefmap_.size() * 512, 128 * 1024));
		}

		for (const auto & [adefid, pdefint] : palertmgr_->adefmap_) {
			if (!pdefint || pdefint->is_deleted() || !pdefint->defstr_.size() || pdefint->is_shyama_handled()) {
				continue;
			}	

			uint32_t		szjson = pdefint->defstr_.size(), minsz = sizeof(SM_ALERT_ADEF_NEW) + szjson + 1 + 7;
			auto			*pstat = (SM_ALERT_ADEF_NEW *)streambuf.get_buf(minsz);
			
			new (pstat) SM_ALERT_ADEF_NEW(adefid, szjson + 1, pdefint->state_.load(mo_relaxed), pdefint->asubsys_, pdefint->isrealtime_, pdefint->is_partha_handled());

			std::memcpy((uint8_t *)(pstat + 1), pdefint->defstr_.data(), szjson);
			((uint8_t *)(pstat + 1))[szjson] = 0;
			 
			streambuf.set_buf_sz(pstat->get_elem_size(), 1);
		}

		return true;
	}
	GY_CATCH_EXPRESSION(
		ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Failed to send Madhava %s Alert Definitions due to exception : %s\n", 
				pmad->print_string(STRING_BUFFER<512>().get_str_buf()), GY_GET_EXCEPT_STRING);
		return false;
	)
}	

int SHCONN_HANDLER::handle_alert_mgr(L2_PARAMS & param)
{
	try {
		MPMCQ_COMM			* const pl2pool = param.pmpmc_;
		const pid_t			tid = gy_gettid();
		bool				bret;
		time_t				tcurr = time(nullptr), tnext = 0;
		ALERTMGR			& alertmgr = *palertmgr_;
		
		do {
			gy_thread_rcu().gy_rcu_thread_offline();

			EV_NOTIFY_ONE		ev;

			tcurr = time(nullptr);

			if (tnext <= tcurr) {
				tnext = tcurr + 1;
			}	
			else if (tnext > tcurr + 60) {
				tnext = tcurr + 60;
			}	

			bret = pl2pool->tryReadUntil(std::chrono::system_clock::from_time_t(tnext), ev);

			try {
				if (bret == true && NOTIFY_DB_WRITE_ARR == ev.get_type()) {
					DB_WRITE_ARR		& dbarr = ev.data_.dbwrarr_;

					if (false == dbarr.validate()) {
						goto nxt1;
					}

					for (size_t i = 0; i < dbarr.ndbs_; ++i) {
						auto 			& dbone		= dbarr.dbonearr_[i];

						uint8_t			*prdbuf 	= dbone.pwrbuf_;
						COMM_HEADER		*phdr 		= (COMM_HEADER *)prdbuf;
						uint8_t			*pendptr	= prdbuf + phdr->get_act_len();	
						const bool		is_last_elem	= (i + 1 == dbarr.ndbs_);
						EVENT_NOTIFY		*pevtnot;
						QUERY_CMD		*pquery;

						switch (phdr->data_type_) {

						case COMM_EVENT_NOTIFY :
					
							pevtnot = (EVENT_NOTIFY *)(phdr + 1);

							switch (pevtnot->subtype_) {

							case NOTIFY_ALERT_STAT_INFO :
								try {
									auto		 	*pstat = (ALERT_STAT_INFO *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									const auto		& madhava_shr = dbarr.shrconn_->get_madhava_shared();
									auto			*pmadhava = madhava_shr.get();
									
									if (pmadhava) {
										alertmgr.handle_alert_stat_info(pmadhava->print_string().get(), pstat, nevents, pendptr);
									}	
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Alert Manager Stats Info Notify : %s\n", GY_GET_EXCEPT_STRING);
								);

								break;
												

							case NOTIFY_ALERT_STAT_CLOSE :
								try {
									auto		 	*pstat = (ALERT_STAT_CLOSE *)(pevtnot + 1);
									int			nevents = pevtnot->nevents_;

									const auto		& madhava_shr = dbarr.shrconn_->get_madhava_shared();
									auto			*pmadhava = madhava_shr.get();
									
									if (pmadhava) {
										alertmgr.handle_alert_stat_close(pmadhava->print_string().get(), pstat, nevents, pendptr);
									}	
								}
								GY_CATCH_EXCEPTION(
									ERRORPRINT_OFFLOAD("Exception occurred while handling Alert Manager Stats Close Notify : %s\n", GY_GET_EXCEPT_STRING);
								);

								break;

							default :
								break;
							
							}

							break;

						case COMM_QUERY_CMD :

							pquery = (QUERY_CMD *)(phdr + 1);

							switch (pquery->subtype_) {
								
							case CRUD_ALERT_JSON :

								try {
									char 			*pjson = (char *)(pquery + 1);

									alertmgr.handle_crud_cmd(dbarr.shrconn_, pquery, pjson, (char *)pendptr);
								}
								GY_CATCH_EXPRESSION(
									char			ebuf[256];
									int			ecode = GY_GET_EXCEPT_CODE();

									if (ecode == 0) ecode = ERR_SERV_ERROR;

									ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Alert Manager Node Command Exception caught : %s\n", GY_GET_EXCEPT_STRING);
									
									auto sret = GY_SAFE_SNPRINTF(ebuf, sizeof(ebuf), "Alert Manager Exception : %s", GY_GET_EXCEPT_STRING);

									send_json_error_resp(dbarr.shrconn_, ERR_CODES_E(ecode), pquery->get_seqid(), ebuf, sret);
								);

								break;

							default :
								break;
							
							}

							break;


						default :
							break;
						}	
					}	

				}
				else if (bret == true && NOTIFY_UNIQ_DATA == ev.get_type()) {
					UNIQ_DATA		& udata = ev.data_.uniq_data_;
					
					/*
					 * This handles the Alerts sent locally by Shyama. Note the alerts are assumed single events
					 */

					switch (udata.type_) {
					
					case NOTIFY_ALERT_STAT_INFO :
						try {
							if (true == udata.validate(sizeof(ALERT_STAT_INFO) + 16)) {
								auto			*pstat = (ALERT_STAT_INFO *)udata.uniq_.get();

								alertmgr.handle_alert_stat_info("Shyama Based Alert", pstat, 1, (uint8_t *)udata.uniq_.get() + udata.lenuniq_);
							}
						}
						GY_CATCH_EXCEPTION(
							ERRORPRINT_OFFLOAD("Exception occurred while handling Alert Manager Shyama Based Stats Info Notify : %s\n", GY_GET_EXCEPT_STRING);
						);

						break;

					case NOTIFY_ALERT_STAT_CLOSE :
						try {
							static_assert(sizeof(udata.extdata_) >= sizeof(ALERT_STAT_CLOSE), "Please change the logic below");

							if (true == udata.validate(0, sizeof(ALERT_STAT_CLOSE))) {
								auto			*pstat = (ALERT_STAT_CLOSE *)udata.extdata_;

								alertmgr.handle_alert_stat_close("Shyama Based Alert", pstat, 1, udata.extdata_ + udata.lenext_);
							}
						}
						GY_CATCH_EXCEPTION(
							ERRORPRINT_OFFLOAD("Exception occurred while handling Alert Manager Shyama Based Stats Close Notify : %s\n", GY_GET_EXCEPT_STRING);
						);

						break;

					default :
						break;
					}	
				}

nxt1 :
				alertmgr.check_schedules(tnext);

			}
			GY_CATCH_EXCEPTION(
				ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Exception caught in Alert Manager Handler while handling message : %s\n\n", GY_GET_EXCEPT_STRING);
			);

		} while (true);	

		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught in Alert Manager : %s\n\n", GY_GET_EXCEPT_STRING);
		return -1;
	);
}


} // namespace shyama
} // namespace gyeeta

