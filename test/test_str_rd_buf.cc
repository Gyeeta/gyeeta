
#include		"gy_common_inc.h"

using namespace gyeeta;

static constexpr const char		*gteststr[] 	{
								"(avg(resp5s) * 1.0)/max(resp5s) as respratio ",
								" (	100.0 * (sum((sererr + (1.2 * clierr))) + 10))/	sum(nqry5s)  as weberrpct",
								"avg(kbin15s + kbout15s)/1024 as avgnwmb",
								"100.0 * avg(kbin15s + (1.2 * kbout15s))/1024 as par1",
								" percentile(0.99, (resp5s)	) 	as	 pctresp5s",
								"(1 + sum(sererr + clierr))/sum(nqry5s) * 100 as weberrpct2",
								"1 + 2 as null1",
							};	

bool is_aggr_operator(const char *colname) noexcept
{
	constexpr const char  		*aoperarr[] { "sum(", "avg(", "max(", "min(", "percentile(" };

	for (size_t i = 0; i < GY_ARRAY_SIZE(aoperarr); ++i) {
		if (0 == strncmp(colname, aoperarr[i], strlen(aoperarr[i]))) {
			return true;
		}	
	}	

	return false;
}								

void tparse_aggr(const char *colname, size_t szcol)
{
	constexpr const char		separators[] = " \t\n\r()+-*/%&|,";
	STR_RD_BUF			rdbuf(colname, szcol);
	STRING_BUFFER<1024>		operbuf, strbuf;
	STRING_BUFFER<320>		colone;
	char				field[24];
	const char			*pas, *ptmp, *ptmp2, *poper, *pfield, *pwrstart, *pend = colname + szcol;
	size_t				nbytes, nfieldbytes;
	uint32_t			fieldcrc;
	bool				operactive = false, isdiv;

	pas = rdbuf.skip_till_whole_word_const("as");
	if (!pas) {
		GY_THROW_EXPRESSION("Query Params : Custom Column \'%s\' does not contain the as <JSON Field> expression e.g. \'max(p95resp5s) as maxp95resp\'", colname);
	}	

	pas -= GY_CONST_STRLEN("as");

	pfield = rdbuf.get_next_word(nfieldbytes, true, separators, true /* skip_leading_space */, true /* ignore_escape */, true /* skip_multi_separators */);
	if (!pfield) {
		GY_THROW_EXPRESSION("Query Params : Custom Column \'%s\' does not contain the as <JSON Field> expression field e.g. \'max(p95resp5s) as maxp95resp\'", colname);
	}	
	else if (nfieldbytes > 24) {
		GY_THROW_EXPRESSION("Query Params : Custom Column \'%s\' has field name as \'%s\' length too long. Please use a different name upto 24 bytes'", colname, pfield);
	}	

	ptmp = rdbuf.get_next_word(nbytes, true, separators);
	if (ptmp) {
		GY_THROW_EXPRESSION("Query Params : Custom Column \'%s\' has field name \'%s\' followed by another word which is not allowed'", colname, pfield);
	}

	rdbuf.reset();
	pwrstart = rdbuf.get_curr_pos();
	strbuf << '(';
	
	do {
		ptmp = rdbuf.get_next_word(nbytes, true, separators);

		if (!ptmp || ptmp >= pas) {
			break;
		}	
		
		if (nbytes) {
			char			c = *ptmp;

			if (operactive == false) {
				if (c >= 'a' && c <= 'z' && is_aggr_operator(ptmp)) {
					int		nlp = 1, nrp = 0;

					operactive 	= true;
					poper 		= ptmp;
					

					do {
						ptmp = rdbuf.skip_till_next_delim("()", 2);

						if (!ptmp || ptmp >= pas) {
							GY_THROW_EXPRESSION("Query Params : Parenthesis mismatch for aggregation column : \'%s\'", colname);
							break;
						}	

						if (ptmp[-1] == '(') {
							nlp++;
						}	
						else if (ptmp[-1] == ')') {
							nrp++;
						}	

						if (*ptmp == '(') {
							nlp++;
							++rdbuf;
						}	
						else if (*ptmp == ')') {
							nrp++;
							++rdbuf;
							ptmp++;
						}	

						if (nlp <= nrp) {
							operbuf << "Operator = \'" << std::string_view(poper, ptmp - poper) << "\' ";

							if (size_t(ptmp - poper) >= sizeof(colone)) {
								GY_THROW_EXPRESSION("Query Params : Custom Column \'%s\' too big an expression. "
									"Please specify a smaller expression upto 300 characters\'", colname);
							}	

							fieldcrc = fnv1_hash(poper, ptmp - poper);

							snprintf(field, sizeof(field), "c%u", fieldcrc);

							operactive = false;

							strbuf.append(pwrstart, poper - pwrstart);

							isdiv = false;

							if (poper > colname) {
								ptmp2 = poper - 1;

								while (ptmp2 >= colname && isspace(*ptmp2)) {
									ptmp2--;
								}	

								if ((*ptmp2 == '/') || (*ptmp2 == '%')) {
									strbuf << "nullif(" << field << ", 0)";
									isdiv = true;
								}	
							}
							
							if (!isdiv) {
								strbuf << field;
							}	
							pwrstart = ptmp;

							break;
						}	
					} while (true);	
				}	
			}
		}
	} while (true);

	strbuf.append(pwrstart, pas - pwrstart);

	strbuf << ')' << "::real ";
	strbuf << pas;


	INFOPRINTCOLOR(GY_COLOR_GREEN, "Column \'%s\' : \n\t\t\t\t\tAggregation operators = %s : \n\t\t\t\t\tPost Aggregation expression is = \'%s\'\n\n", 
						colname, operbuf.buffer(), strbuf.buffer());
}	


int main(int argc, char **argv)
{
	try {

		const char			*pstring = "( ({ p99resp5s > 1 }) and ({ avgnwkb > 1 }) )";

		if (argc == 2) {
			if ((0 == strcmp(argv[1], "--help")) || (0 == strcmp(argv[1], "-h"))) {
				IRPRINT("\n\nUsage : %s <Optional string to be parsed>\n\ne.g. %s \'( ({ p99resp5s > 1 }) and ({ avgnwkb > 1 }) )\' \n\n", argv[0], argv[0]);
				return -1;
			}

			pstring = argv[1];
		}	

		STR_RD_BUF			rdbuf(pstring);
		STRING_BUFFER<1024>		strbuf;
		std::vector<std::string>	svec;
		const char			*strvec[1024];
		size_t				szvec[GY_ARRAY_SIZE(strvec)], nwords;
		constexpr const char		separators[] = " \t\n\r(){}><+-*/=%&|!,";

		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Input string to be parsed is \"%s\"\n\n", pstring);

		
		const char			*ptmp;
		size_t				nbytes;
		
		do {
			ptmp = rdbuf.get_next_word(nbytes, true, separators);

			if (!ptmp) {
				break;
			}	

			svec.emplace_back(ptmp, nbytes);

			strbuf.append(ptmp, nbytes);

			strbuf << ptmp[nbytes] << ' ';
		} while (true);

		INFOPRINTCOLOR(GY_COLOR_CYAN, "The parsed string contains %lu words : \n\t\t\t\t[", svec.size());

		for (const auto & str : svec) {
			IRPRINTCOLOR(GY_COLOR_CYAN, "\"%s\", ", str.c_str());
		}	

		IRPRINT("\n\n");

		nwords = rdbuf.get_word_list(strvec, szvec, GY_ARRAY_SIZE(strvec), true, separators, true /* ignore_escape */, true /* skip_multi_separators */);

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Using get_word_list() with skip_multi_separators set, the parsed string contains %lu words : \n\t\t\t\t[", nwords);

		for (size_t i = 0; i < nwords; ++i) {
			IRPRINT("\"");
			fwrite(strvec[i], szvec[i], 1, stdout);
			IRPRINT("\", ");
		}	

		IRPRINT("\n\n");


		INFOPRINTCOLOR(GY_COLOR_CYAN, "The string buffer contents is \'%s\'\n\n", strbuf.buffer());

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Now testing aggregation column parsing...\n\n");

		for (const char *pcol : gteststr) {
			try {
				tparse_aggr(pcol, strlen(pcol));
			}
			GY_CATCH_EXPRESSION(
				ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while parsing the column : %s\n", GY_GET_EXCEPT_STRING);
			);
		}	

	}
	GY_CATCH_EXPRESSION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while parsing : %s\n", GY_GET_EXCEPT_STRING);
	);
}


