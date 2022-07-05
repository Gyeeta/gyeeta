
#include			"gy_boolparse.h"

#include			<iostream>

using namespace gyeeta;

int main()
{
	std::string		input;

	IRPRINT("\n\n");
	INFOPRINT("Enter a logical expression to parse : \n\tFor e.g. \'( ( { p95resp5s < resp5s } or { kbin15s + kbout15s > 1 } ) and { cluster like 'cl[5-9].*' } )\' : ");

	while (std::getline(std::cin, input)) {
		try {
			INFOPRINTCOLOR(GY_COLOR_CYAN, "Parsing expr : \'%s\' : \n\n", input.data());

			GY_BOOLPARSE			boolparse(input.data(), input.size());
			uint32_t 			ncritgroups, nl2groups, nl1_crit, max1crit, total_crit;
			bool 				is_l1_and;

			boolparse.get_stats(ncritgroups, nl2groups, nl1_crit, is_l1_and, max1crit, total_crit);

			std::string_view 		critarr[64];

			IRPRINT("\t\tExpr has %u groups, %u Max Criteria in 1 Group and %u Total Disjunctive Normalized Criteria : \n\n", ncritgroups, max1crit, total_crit);

			for (size_t i = 0; i < ncritgroups; ++i) {
				uint32_t 		ncrit = boolparse.get_group_criteria(i, critarr, GY_ARRAY_SIZE(critarr));

				IRPRINT("\t\t");

				for (size_t j = 0; j < ncrit; ++j) {
					IRPRINT("{ Criteria #%lu : \'%s\' }  %s  ", j + 1, CHAR_BUF<4096>(critarr[j]).get(), j + 1 < ncrit ? (ncrit > 1 ? "AND" : "OR") : "");
				}

				if (i + 1 < ncritgroups) {
					IRPRINT("\n\tOR\n");
				}	
			}	

			IRPRINT("\n\n");
		}
		GY_CATCH_EXPRESSION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while parsing criteria : %s\n\n", GY_GET_EXCEPT_STRING);
		);

		INFOPRINT("Enter the next logical expression or press <Ctrl-C> to exit... : ");
	}	
}

