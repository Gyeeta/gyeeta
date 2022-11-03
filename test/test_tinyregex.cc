//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include		"gy_tinyregex.h"

int match_filter(const char *pregex, int precreate)
{
	INFOPRINT("Starting tinyregex tests...\n\n");

	std::optional<gyeeta::TinyRegex>	reg;
	char					inputbuf[512];
	uint64_t				t1, t2;
	bool					bret;

	using gyeeta::get_nsec_clock;

	if (precreate) {
		INFOPRINT("Compiling regex string \'%s\' \n", pregex);

		t1 = get_nsec_clock();

		reg.emplace((const char *)pregex, false /* throw_on_error */);
	
		t2 = get_nsec_clock();

		INFOPRINT("Regex Object created : Time taken = %lu nsec (%lu usec)\n", t2 - t1, (t2 - t1)/1000);

		if ((reg->is_valid()) == false) {
			ERRORPRINT("Could not compile regular expression %s : Error is \'%s\'\n\n", pregex, reg->get_error());
			return -1;
		}
	}
	

	IRPRINT("\n\n");
	
	do {
		const char		*pmatchstart;
		int			matchlen;

		INFOPRINT("Enter Test String : ");
		scanf("%500[^\n]", inputbuf);
		getchar();

		t1 = get_nsec_clock();

		if (precreate) {
			bret = reg->regex_match_compiled((const char *)inputbuf, reg.value(), &pmatchstart, &matchlen);
		}
		else {
			// bret = TinyRegexInt<24>::regex_match((const char *)inputbuf, pregex, true /* throw_on_error */);

			bret = gyeeta::TinyRegex::regex_match((const char *)inputbuf, pregex, true /* throw_on_error */, false /* is_case_insensitive */ , &pmatchstart, &matchlen);
		}	

		t2 = get_nsec_clock();

		if (bret == true) {
			INFOPRINT("String \'%s\' matches regex : \'%s\' : Match started at \'%s\' of length %d : Time taken for match = %lu nsec (%lu usec)\n\n", 
					inputbuf, pregex, pmatchstart, matchlen, t2 - t1, (t2 - t1)/1000);
		}
		else {
			INFOPRINT("String \'%s\' does not match regex : \'%s\' : Time taken for match = %lu nsec (%lu usec)\n\n", inputbuf, pregex, t2 - t1, (t2 - t1)/1000);
		}

	} while (1);

	return 1;
}


int main(int argc, char **argv)
{
	gyeeta::gdebugexecn = 20;

	if (argc < 2) {
		IRPRINT("\nERROR : Usage %s <Regex String> <Precreate regex object 0/1 default 1>\n\n", argv[0]);
		return -1;	
	}	

	try {
		match_filter(argv[1], argc > 2 ? atoi(argv[2]) : 1);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while testing regex : %s\n\n", GY_GET_EXCEPT_STRING);
	);
}

