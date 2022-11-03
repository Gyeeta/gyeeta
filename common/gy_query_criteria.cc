//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_query_criteria.h"
#include			"gy_boolparse.h"
#include			"gy_print_offload.h"
#include			"gy_stack_container.h"

namespace gyeeta {

static const JSON_DB_MAPPING * get_expr_field(const char *pstart, uint32_t nsz, const JSON_DB_MAPPING **pjson_map, size_t szmap, const char *subsys_str) 
{
	const char 		*ptmp = (const char *)memchr(pstart, '.', nsz), *pend = pstart + nsz;
	const JSON_DB_MAPPING	*pcol = nullptr;

	if (ptmp) {
		if (pend > ptmp) {
			pcol = get_jsoncrc_mapping(ptmp + 1, pend - ptmp - 1, pjson_map, szmap);
		}

		if (!pcol && ((0 != memcmp(pstart, subsys_str, ptmp - pstart)) || (subsys_str[ptmp - pstart] != 0))) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion : \'%s\' column specified is not a valid column for Subsystem \'%s\' or was skipped due to Custom Columns",
				CHAR_BUF<128>(pstart, ptmp - pstart).get(), subsys_str);
		}
	}	
	else {
		pcol = get_jsoncrc_mapping(pstart, nsz, pjson_map, szmap);
	}	

	return pcol; 
}

CRITERION_ONE::CRITERION_ONE(const char * pone, size_t szone, uint64_t hash, SUBSYS_CLASS_E subsys, const char *subsys_str, const JSON_DB_MAPPING **psubsys_map, uint32_t nmap_fields, EXT_POOL_ALLOC *pextpool, bool allocregex)
	: subsys_str_(subsys_str), subsys_(subsys), hash_(hash)
{
	if (!subsys_str || !psubsys_map || !nmap_fields) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion Parameters : Subsystem fields empty");
	}

	char			buf1[MAX_ONE_CRITERION_LEN], subbuf[64];
	const char		*ptmp, *pend, *pstart;
	const char		*fieldstr, *operstr, *valstr, *currval, *currend;			
	uint32_t		subnamelen;
	bool			is_in = false, is_regex = false;

	if (szone >= sizeof(buf1)) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion Length : Too large %lu : Max allowed is %lu", szone, sizeof(buf1) - 1);
	}

	subnamelen = GY_SAFE_SNPRINTF(subbuf, sizeof(subbuf), "%s.", subsys_str);

	try {
		std::memcpy(buf1, pone, szone);
		buf1[szone] = 0;
		
		ptmp = buf1;
		pend = buf1 + szone;

		while (ptmp < pend && (*ptmp == ' ' || *ptmp == '\t' || *ptmp == '(')) ptmp++;

		if (ptmp == pend) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Must be of type : <Field> <Operator> <Value> : %.*s", int(szone > 128 ? 128 : szone), buf1);
		}	

		if (0 == memcmp(ptmp, subbuf, subnamelen)) {
			ptmp += subnamelen;
		}	
		else if (0 == memcmp(ptmp, "host.", 5)) {
			ptmp += 5;
			
			if (subsys != SUBSYS_HOST) {
				subsys_ = SUBSYS_HOST;
				subsys_str = "host";
				subnamelen = GY_SAFE_SNPRINTF(subbuf, sizeof(subbuf), "%s.", subsys_str);
			}
		}	

		if (ptmp + 2 >= pend) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Must be of type : <Field> <Operator> <Value> : %.*s", int(szone > 128 ? 128 : szone), buf1);
		}	

		fieldstr = ptmp;

		while (ptmp < pend && (*ptmp != ' ' && *ptmp != '\t')) ptmp++;

		if (ptmp == pend) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Must be of type : <Field> <Operator> <Value> : %.*s", int(szone > 128 ? 128 : szone), buf1);
		}	

		pfield1_ = get_expr_field(fieldstr, ptmp - fieldstr, psubsys_map, nmap_fields, subsys_str);

		if (!pfield1_) {
			if (0 == memcmp(fieldstr, "now()", GY_CONST_STRLEN("now()"))) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion : now() function specified at start for %s : Expression must start with a subsystem column"
					": e.g. use : { tstart + 300 > now() } to indicate a service started in last 5 min (300 sec)", fieldstr);
			}	

			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion : Invalid Column name \'%.*s\' specified for Subsytem \'%s\' : "
					"Expression must start with a valid subsystem column and must not contain a column skipped due to Custom columns", 
					int(ptmp - fieldstr), fieldstr, subsys_str);
		}

		if (subsys_ != SUBSYS_HOST && pfield1_->subsys == SUBSYS_HOST) {
			subsys_	= SUBSYS_HOST;
			subsys_str = "host";
			subnamelen = GY_SAFE_SNPRINTF(subbuf, sizeof(subbuf), "%s.", subsys_str);
		}

		fieldtype_ 		= pfield1_->jsontype;
		is_timestamp_sec_	= ((pfield1_->jsontype == JSON_STRING) && (0 == strcmp(pfield1_->dbtype, "timestamptz"))); 

		while (ptmp < pend && (*ptmp == ' ' || *ptmp == '\t')) ptmp++;

		if (ptmp == pend) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Missing Value : Must be of type : <Field> <Operator> <Value> : %.*s", int(szone > 128 ? 128 : szone), buf1);
		}	

		operstr = ptmp++;

		while (ptmp < pend && (*ptmp != ' ' && *ptmp != '\t')) ptmp++;

		if (ptmp == pend) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Must be of type : <Field> <Operator> <Value> : %.*s", int(szone > 128 ? 128 : szone), buf1);
		}	

		if (ptmp - operstr == 1 && (fieldtype_ == JSON_NUMBER || is_timestamp_sec_)) {
			// Check for math operators
			switch (*operstr) {
			
			case '+' :
			case '-' :
			case '*' :
			case '/' :
			case '%' :
			case '&' :
			case '|' :
				math_oper_ = *operstr;
				break;
			
			default :
				break;
			}	

			if (math_oper_) {

				if (is_timestamp_sec_ && math_oper_ != '+' && math_oper_ != '-') {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Operator \'%c\' not valid for Timestamp field", math_oper_);
				}

				while (ptmp < pend && (*ptmp == ' ' || *ptmp == '\t')) ptmp++;

				if (ptmp == pend) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Missing Value : Must be of type : <Field> <Operator> <Value> : %.*s", 
							int(szone > 128 ? 128 : szone), buf1);
				}	

				operstr = ptmp++;

				while (ptmp < pend && (*ptmp != ' ' && *ptmp != '\t')) ptmp++;

				if (ptmp == pend) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Must be of type : <Field> <Operator> <Value> : %.*s", 
							int(szone > 128 ? 128 : szone), buf1);
				}	

				if ((operstr + 3 >= pend) || (!std::isalpha(*operstr))) {
					// Check if its a constant
					char			*pextraend = nullptr;

					if (!string_to_number(operstr, field2_const_, &pextraend)) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Must be of type : <Field> %c <Same Subsytem.field> : %.*s", 
									math_oper_, int(szone > 128 ? 128 : szone), buf1);
					}
					
					if (field2_const_ == 0 && (math_oper_ == '/' || math_oper_ == '%')) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Divide by Zero seen for operator %c : %.*s", 
									math_oper_, int(szone > 128 ? 128 : szone), buf1);
					}	

					if (pextraend && pextraend < pend && !is_space_tab(*pextraend)) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Expression \'%s\' on Constants not currently supported", pextraend);
					}	

					if (std::trunc(field2_const_) != field2_const_) {
						if (pfield1_->numtype != NUM_DOUBLE && !is_timestamp_sec_) {
							force_double_ = true;
						}	
					}	
				}	
				else {
					fieldstr = (const char *)memchr(operstr, '.', ptmp - operstr);

					if (fieldstr) {
						fieldstr++;
					}	
					else {
						fieldstr = operstr;
					}	

					pfield2_ = get_expr_field(fieldstr, ptmp - fieldstr, psubsys_map, nmap_fields, subsys_str);

					if (!pfield2_) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion : Invalid Field name \'%.*s\' specified for Subsytem \'%s\'", 
									int(ptmp - fieldstr), fieldstr, subsys_str);
					}
				
					if (pfield2_->jsontype != JSON_NUMBER) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format"
									" : %s not numeric : Must be of type : <Field> %c <Same Subsytem.field of Numeric type> : %.*s", 
									pfield2_->jsonfield, math_oper_, int(szone > 128 ? 128 : szone), buf1);
					}	
				}

				while (ptmp < pend && (*ptmp == ' ' || *ptmp == '\t')) ptmp++;

				if (ptmp == pend) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Missing Value : Must be of type : <Field> <Operator> <Value> : %.*s", 
								int(szone > 128 ? 128 : szone), buf1);
				}	

				operstr = ptmp++;

				while (ptmp < pend && (*ptmp != ' ' && *ptmp != '\t')) ptmp++;

				if (ptmp == pend) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Must be of type : <Field> <Operator> <Value> : %.*s", 
								int(szone > 128 ? 128 : szone), buf1);
				}	
			}	
		}

		auto		pcomp = get_jsoncrc_mapping(operstr, ptmp - operstr, comparator_map, GY_ARRAY_SIZE(comparator_map));
		
		if (!pcomp) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion : Invalid Comparator \'%.*s\' specified for field \'%s\'", 
						int(ptmp - operstr), operstr, pfield1_->jsonfield);
		}	

		if (pcomp->isvalid[fieldtype_] == false) {
			if (is_timestamp_sec_ && pcomp->compval >= COMP_LT && pcomp->compval <= COMP_GE) {
				// <, > valid for timestamptz
			}
			else {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion : Comparator \'%.*s\' not valid for field \'%s\'", 
						int(ptmp - operstr), operstr, pfield1_->jsonfield);
			}
		}

		comp_ = pcomp->compval;

		is_in 		= (comp_ == COMP_IN || comp_ == COMP_NOTIN);
		is_regex 	= (comp_ == COMP_LIKE || comp_ == COMP_NOTLIKE);

		while (ptmp < pend && (*ptmp == ' ' || *ptmp == '\t')) ptmp++;

		if (ptmp == pend) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Missing Value : Must be of type : <Field> <Operator> <Value> : %.*s", 
						int(szone > 128 ? 128 : szone), buf1);
		}	

		valstr = ptmp;
		
		if (fieldtype_ == JSON_NUMBER) {

			currval = valstr;

			if (false == NUMBER_CRITERION::valid_start_string(currval)) {

				// Check if its an expression

				if (pcomp->isvalid[JSON_EXPR_TYPE] == false) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' not a valid Number for field \'%s\'", 
						CHAR_BUF<128>(currval, pend - currval).get(), pfield1_->jsonfield);
				}	
				else {
					while (ptmp < pend && (*ptmp != ' ' && *ptmp != '\t' && *ptmp != ',')) ptmp++;
					currend = ptmp;

					auto 		pexp = get_expr_field(currval, ptmp - currval, psubsys_map, nmap_fields, subsys_str);

					if (!pexp) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' not valid for field \'%s\'", 
							CHAR_BUF<128>(currval, ptmp - currval).get(), pfield1_->jsonfield);

					}	
					else if (pexp->jsontype != JSON_NUMBER) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' not a valid Number for field \'%s\'", 
							CHAR_BUF<128>(currval, ptmp - currval).get(), pfield1_->jsonfield);

					}	

					pexpr_val_ 	= pexp;
					valtype_	= JSON_NUMBER;

					is_valid_ 	= true;
				}	
			}
			else if (is_in == false) {	
				double			d;
				char			*pextra = nullptr;

				if (!string_to_number(currval, d, &pextra)) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' not a valid Number for field \'%s\'", 
						CHAR_BUF<128>(currval, pend - currval).get(), pfield1_->jsonfield);
				}

				if (pextra && pextra <= pend) {
					ptmp = pextra;
				}	
				else {
					ptmp = pend;
				}	

				if (std::trunc(d) != d) {
					if (pfield1_->numtype != NUM_DOUBLE && !is_timestamp_sec_) {
						force_double_ = true;
					}	

					numval_.emplace(d);
				}
				else {
					numval_.emplace((int64_t)d);
				}	

				if (false == numval_->is_valid()) {

					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' not a valid Number for field \'%s\'", 
						CHAR_BUF<128>(currval, pend - currval).get(), pfield1_->jsonfield);
				}	

				valtype_	= JSON_NUMBER;
				is_valid_ 	= true;
			}
			else {
				parse_num_in_clause(currval, pend, pfield1_->jsonfield, pfield1_->numtype, pextpool);
				
				valtype_	= JSON_NUMBER;
				is_valid_ 	= true;

				return;
			}	

		}	
		else if (fieldtype_ == JSON_STRING) {
			
			currval = valstr;

			if (false == STRING_CRITERION::valid_start_string(currval)) {

				// Check if its an expression

				if (pcomp->isvalid[JSON_EXPR_TYPE] == false) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' not a valid String for field \'%s\'", 
						CHAR_BUF<128>(currval, pend - currval).get(), pfield1_->jsonfield);
				}	
				else {
					while (ptmp < pend && (*ptmp != ' ' && *ptmp != '\t' && *ptmp != ',')) ptmp++;

					currend = ptmp;

					auto 		pexp = get_expr_field(currval, ptmp - currval, psubsys_map, nmap_fields, subsys_str);

					if (!pexp) {
						if (is_timestamp_sec_ && 0 == memcmp(currval, "now()", GY_CONST_STRLEN("now()"))) {

							numval_.emplace(time(nullptr));
							is_time_func_ = true;

							if (0 == math_oper_ && field2_const_ == 0) {
								while (ptmp < pend && (is_space_tab(*ptmp))) ptmp++;
								
								if (ptmp + 3 < pend) {
									if ((*ptmp == '+' || *ptmp == '-') && is_space_tab(ptmp[1])) {
										int64_t			fval;
										char			*pextraend = nullptr;
										char			c1 = *ptmp;

										ptmp += 2;

										if ((!string_to_number(ptmp, fval, &pextraend)) || (pextraend && *pextraend == '.')) {
											GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, 
												"Invalid Criterion format : Must be of type : <Field> <Comparator> now() +/- <integer seconds> : \'%s\'", 
														currval);
										}

										math_oper_ = (c1 == '+' ? '-' : '+');
										field2_const_ = fval;

										if (pextraend) {
											ptmp = pextraend;
										}	
									}
								}	

								currend = ptmp;
							}
						}
						else {
							GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' not valid for field \'%s\'", 
									CHAR_BUF<128>(currval, ptmp - currval).get(), pfield1_->jsonfield);
						}
					}	
					else if (pexp->jsontype != JSON_STRING) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' not a valid String for field \'%s\'", 
							CHAR_BUF<128>(currval, ptmp - currval).get(), pfield1_->jsonfield);

					}	
					else {
						pexpr_val_ = pexp;
					}

					valtype_	= JSON_STRING;

					is_valid_ 	= true;
				}	
			}
			else if (is_in == false) {	
				ptmp = ++currval;
		
				while (ptmp < pend && (*ptmp != '\'')) ptmp++;

				if (ptmp == pend) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' string delimiter \' missing for field \'%s\'", 
								currval, pfield1_->jsonfield);
				}	

				if (ptmp + 1 < pend && ptmp[1] != ' ' && ptmp[1] != '\t') {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' : Quote \' only allowed for start and end of string for field \'%s\'", 
								currval, pfield1_->jsonfield);
				}	

				strval_.emplace(currval, ptmp - currval, pextpool);

				if (false == strval_->is_valid()) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' not a valid string for field \'%s\'", 
						CHAR_BUF<128>(currval, pend - currval).get(), pfield1_->jsonfield);
				}	

				ptmp++;
				
				if (is_timestamp_sec_) {
					time_t			tsec = gy_iso8601_to_time_t(strval_->get());

					if (tsec == 0) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Timestamp Criterion  : Value \'%s\' for field \'%s\'", strval_->get(), pfield1_->jsonfield);
					}	

					numval_.emplace(tsec);
				}	

				if (is_regex) {
					if (is_timestamp_sec_) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Regex for Timestamp Criterion field \'%s\' not allowed", pfield1_->jsonfield);
					}

					strval_->set_ign_case();

					pregex_ = (decltype(pregex_))EXT_POOL_ALLOC::opt_safe_malloc(pextpool, sizeof(*pregex_), regex_free_fp_);

					new (pregex_) std::optional<RE2>();

					if (allocregex) {
						init_regex();
					}
				}	

				valtype_ 	= JSON_STRING;
				is_valid_ 	= true;
			}
			else {
				if (is_timestamp_sec_) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "In Clause for Timestamp Criterion field \'%s\' not allowed", pfield1_->jsonfield);
				}

				parse_str_in_clause(currval, pend, pfield1_->jsonfield, pextpool);
				
				valtype_ 	= JSON_STRING;
				is_valid_ 	= true;

				return;
			}	
		}
		else if (fieldtype_ == JSON_BOOL) {
			currval = valstr;

			if (false == BOOL_CRITERION::valid_string(currval)) {

				// Check if its an expression

				if (pcomp->isvalid[JSON_EXPR_TYPE] == false) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' not a valid Boolean for field \'%s\'", 
						CHAR_BUF<128>(currval, pend - currval).get(), pfield1_->jsonfield);
				}	
				else {
					while (ptmp < pend && (*ptmp != ' ' && *ptmp != '\t' && *ptmp != ',')) ptmp++;
					currend = ptmp;

					auto 		pexp = get_expr_field(currval, ptmp - currval, psubsys_map, nmap_fields, subsys_str);

					if (!pexp) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' not valid for field \'%s\'", 
							CHAR_BUF<128>(currval, ptmp - currval).get(), pfield1_->jsonfield);

					}	
					else if (pexp->jsontype != JSON_BOOL) {
						GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' not a valid Boolean for field \'%s\'", 
							CHAR_BUF<128>(currval, ptmp - currval).get(), pfield1_->jsonfield);

					}	

					pexpr_val_ 	= pexp;
					valtype_	= JSON_BOOL;

					is_valid_ 	= true;
				}	
			}
			else {
				boolval_.emplace(currval);

				if (false == boolval_->is_valid()) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' not a valid boolean type for field \'%s\'", 
						CHAR_BUF<128>(currval, pend - currval).get(), pfield1_->jsonfield);
				}	

				valtype_ 	= JSON_BOOL;
				is_valid_ 	= true;

				if (*currval == 't') {
					ptmp += 4;
				}	
				else {
					ptmp += 5;
				}	
			}
		}	
		else {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Field \'%s\' not a valid type for criterion", pfield1_->jsonfield);
		}	

		while (ptmp < pend && (*ptmp == ' ' || *ptmp == '\t')) ptmp++;

		if (ptmp < pend) {
			if (*ptmp != '}' && *ptmp != ')') {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Extra Characters seen at end of Expression \'%s\' : "
						"Cannot have Value with expression in <Field> <Operator> <Value>", ptmp);
			}
		}	
	}
	catch(...) {
		destroy();
		throw;
	}	
}	

void CRITERION_ONE::parse_num_in_clause(const char *pin, const char *pend, const char *jsonfield, NUMBER_TYPES_E numtype, EXT_POOL_ALLOC *pextpool)
{
	const char			*pstartnum = pin, *ptmp = pin, *pendnum;
	size_t				nelems = 0;
	std::pair<const char *, size_t>	tarray[MAX_COMP_IN_ELEMS + 1];

	do {
		while (ptmp < pend && (*ptmp == ' ' || *ptmp == '\t' || *ptmp == ',')) ptmp++;
		pstartnum = ptmp++;

		if (false == NUMBER_CRITERION::valid_start_string(pstartnum)) {
			if (pstartnum >= pend) {
				break;
			}	
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%.*s\' not a valid Number for field \'%s\'", 
						int(pend - pstartnum), pstartnum, jsonfield);
		}	

		while (ptmp < pend && (*ptmp != ' ' && *ptmp != '\t' && *ptmp != ',')) ptmp++;
		pendnum = ptmp;

		tarray[nelems++] = {pstartnum, pendnum - pstartnum};

	} while (ptmp < pend && nelems < GY_ARRAY_SIZE(tarray));

	if (nelems == GY_ARRAY_SIZE(tarray)) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Max elements for \'in\' expression reached %lu for field \'%s\'", 
					GY_ARRAY_SIZE(tarray), jsonfield);
	}	

	pnumarray_ = (NUMBER_CRITERION *)EXT_POOL_ALLOC::opt_safe_malloc(pextpool, nelems * sizeof(NUMBER_CRITERION), arr_free_fp_);
	
	for (nin_elems_ = 0; nin_elems_ < nelems; ++nin_elems_) {
		new (pnumarray_ + nin_elems_) NUMBER_CRITERION(tarray[nin_elems_].first, numtype);

		if (false == pnumarray_[nin_elems_].is_valid()) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' not a valid Number for field \'%s\'", 
				CHAR_BUF<128>(tarray[nin_elems_].first, tarray[nin_elems_].second).get(), jsonfield);
		}	
	}	
}

void CRITERION_ONE::parse_str_in_clause(const char *pin, const char *pend, const char *jsonfield, EXT_POOL_ALLOC *pextpool)
{
	const char			*pstartstr = pin, *ptmp = pin, *pendstr;
	size_t				nelems = 0;
	std::pair<const char *, size_t>	tarray[MAX_COMP_IN_ELEMS + 1];

	do {
		while (ptmp < pend && (*ptmp == ' ' || *ptmp == '\t' || *ptmp == ',')) ptmp++;

		pstartstr = ptmp++;

		if (pstartstr >= pend) {
			break;
		}	

		if (false == STRING_CRITERION::valid_start_string(pstartstr)) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%.*s\' not a valid String type as quote missing for field \'%s\'", 
						int(pend - pstartstr), pstartstr, jsonfield);
		}	
		pstartstr++;

		while (ptmp < pend && (*ptmp != '\'')) ptmp++;

		if (ptmp == pend) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%.*s\' string delimiter \' missing for field \'%s\'", 
						int(pend - pstartstr), pstartstr, jsonfield);
		}	

		pendstr = ptmp++;

		if (pstartstr >= pendstr) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Invalid Value \'%s\' for field \'%s\'", pstartstr, jsonfield);
		}

		tarray[nelems++] = {pstartstr, pendstr - pstartstr};

	} while (ptmp < pend && nelems < GY_ARRAY_SIZE(tarray));

	if (nelems == GY_ARRAY_SIZE(tarray)) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Max elements for \'in\' expression reached %lu for field \'%s\'", GY_ARRAY_SIZE(tarray), jsonfield);
	}	
	else if (nelems == 0) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' no valid strings within the \'in\' clause for field \'%s\'", 
			CHAR_BUF<128>(pin, pend - pin).get(), jsonfield);
	}
	
	pstrarray_ = (STRING_CRITERION *)EXT_POOL_ALLOC::opt_safe_malloc(pextpool, nelems * sizeof(STRING_CRITERION), arr_free_fp_);
	
	for (nin_elems_ = 0; nin_elems_ < nelems; ++nin_elems_) {
		new (pstrarray_ + nin_elems_) STRING_CRITERION(tarray[nin_elems_].first, tarray[nin_elems_].second, pextpool);

		if (false == pstrarray_[nin_elems_].is_valid()) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criterion format : Value \'%s\' not a valid String type", 
				CHAR_BUF<128>(tarray[nin_elems_].first, tarray[nin_elems_].second).get());
		}	
	}	
}

CRITERIA_SET::CRITERIA_SET(const char *filter, size_t lenfil, SUBSYS_CLASS_E subsys, EXT_POOL_ALLOC *pextpool, bool is_multihost, bool allocregex)
{
	GY_BOOLPARSE			boolparse(filter, lenfil);
	
	if (boolparse.get_total_criteria() == 0) {
		return;
	}	

	try {
		SUBSYS_CLASS_E		allowed_subsys_arr[] 	{subsys, SUBSYS_HOST};
		uint32_t		nsubsys = (is_multihost ? 2 : 1);
		
		const auto		*psubsysinfo = get_subsys_info(subsys);

		if (!psubsysinfo) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Subsystem %u for Criteria Definition", subsys);
		}	

		const JSON_DB_MAPPING 	*subsys_col_arr[psubsysinfo->szjsonmap + GY_ARRAY_SIZE(json_db_host_arr)];
		uint32_t		ncol_arr = 0;
		const char		*subsys_str = psubsysinfo->jsonstr;

		if (is_multihost && AHDLR_MADHAVA == get_subsys_handler(subsys)) {
			for (size_t i = 0; i < GY_ARRAY_SIZE(json_db_host_arr); ++i) {
				subsys_col_arr[ncol_arr++] = json_db_host_arr + i;
			}	
		}	

		for (size_t i = 0; i < psubsysinfo->szjsonmap; ++i) {
			subsys_col_arr[ncol_arr++] = psubsysinfo->pjsonmap + i;
		}	

		if (is_multihost && AHDLR_SHYAMA == get_subsys_handler(subsys)) {
			for (size_t i = 0; i < GY_ARRAY_SIZE(json_db_host_arr); ++i) {
				subsys_col_arr[ncol_arr++] = json_db_host_arr + i;
			}	
		}	

		populate_groups(boolparse, subsys_str, subsys_col_arr, ncol_arr, pextpool, allowed_subsys_arr, nsubsys, is_multihost, allocregex);
	}
	catch(...) {
		destroy();
		throw;
	}	
}

CRITERIA_SET::CRITERIA_SET(const char *filter, size_t lenfil, SUBSYS_CLASS_E subsys, const char *subsys_str, const JSON_DB_MAPPING **psubsys_map, uint32_t nmap_fields, 
						EXT_POOL_ALLOC *pextpool, bool is_multihost, bool allocregex)
{
	if (!subsys_str || !psubsys_map || !nmap_fields) {
		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Invalid Criteria Input Parameters : subsystem info not populated");
	}

	GY_BOOLPARSE			boolparse(filter, lenfil);

	if (boolparse.get_total_criteria() == 0) {
		return;
	}	

	try {
		SUBSYS_CLASS_E		allowed_subsys_arr[] 	{subsys, SUBSYS_HOST};
		uint32_t		nsubsys = (is_multihost ? 2 : 1);
			
		populate_groups(boolparse, subsys_str, psubsys_map, nmap_fields, pextpool, allowed_subsys_arr, nsubsys, is_multihost, allocregex);
	}
	catch(...) {
		destroy();
		throw;
	}	
}

void CRITERIA_SET::populate_groups(GY_BOOLPARSE & boolparse, const char *subsys_str, const JSON_DB_MAPPING **psubsys_map, uint32_t nmap_fields, EXT_POOL_ALLOC *pextpool, const SUBSYS_CLASS_E *pallowed_subsys_arr, size_t nsubsys, bool is_multihost, bool allocregex)
{
	using SubSysSet 		= INLINE_STACK_HASH_SET<SUBSYS_CLASS_E, 512>;

	SubSysSet			subsys_set;

	uint32_t 			ntotalgroups, nl2groups, nl1_crit, max1crit, total_crit;
	uint32_t			tl1_crit = 0;
	bool 				is_l1_and;

	boolparse.get_stats(ntotalgroups, nl2groups, nl1_crit, is_l1_and, max1crit, total_crit);

	if (ntotalgroups > MAX_CRITERIA_GROUPS) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Criteria : Max limit of criteria groups %lu limit breached (%u) : Please reduce the Filter", 
						MAX_CRITERIA_GROUPS, ntotalgroups);
	}	

	if (max1crit > MAX_ONE_GROUP_CRITERIA) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criteria : Max limit of criteria within a group limit (%lu) breached : %u : Please reduce the Filter", 
				MAX_ONE_GROUP_CRITERIA, max1crit);
	}	

	l1_oper_			= is_l1_and ? OPER_AND : OPER_OR;

	if (nl2groups) {
		pl2_grp_ = (CRITERIA_ONE_GROUP *)EXT_POOL_ALLOC::opt_safe_malloc(pextpool, nl2groups * sizeof(CRITERIA_ONE_GROUP), arr_free_fp_);
	}

	if (nl1_crit) {
		l1_grp_ = CRITERIA_ONE_GROUP(nl1_crit, l1_oper_, 1 /* level */, pextpool, allocregex);
	}	

	std::string_view 		critarr[max1crit];
	CRITERIA_ONE_GROUP		*pcurrgrp = nullptr;
	CRITERION_ONE			*pcritone = nullptr;

	for (uint32_t i = 0; i < ntotalgroups; ++i) {
		uint32_t 		ncrit = boolparse.get_group_criteria(i, critarr, max1crit);

		if (ncrit > 1) {
			if (ntotalgroups == 1) {
				pcurrgrp = &l1_grp_;
			}	
			else if (nl2_group_ < nl2groups) {
				pcurrgrp = pl2_grp_ + nl2_group_++;

				new (pcurrgrp) CRITERIA_ONE_GROUP(ncrit, OPER_AND, 2 /* level */, pextpool);
			}
			else {
				continue;
			}
		}
		else {
			pcurrgrp = &l1_grp_;
		}	
			
		for (size_t j = 0; j < ncrit; ++j) {
			const char		*pstr = critarr[j].data();
			size_t			lenstr = critarr[j].length(), fhash = fnv1_hash(pstr, lenstr);

			pcritone = pcurrgrp->add_criterion(pstr, lenstr, fhash, pallowed_subsys_arr[0], subsys_str, psubsys_map, nmap_fields, 
						pextpool, is_multihost /* check_dollar_quote */, allocregex);

			if (pcritone) {
				total_crit_++;
				subsys_set.emplace(pcritone->get_subsys());
			}	
		}
	}	
	
	if (total_crit_ == 0) {
		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Criteria Error : No valid criteria found or an internal error occured");
	}	

	if (pallowed_subsys_arr && nsubsys > 0) {
		size_t			s;

		for (SUBSYS_CLASS_E sub : subsys_set) {

			for (s = 0; s < nsubsys; ++s) {
				if (pallowed_subsys_arr[s] == sub) {
					break;
				}	
			}	

			if (s == nsubsys) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Subsystem seen for query criteria \'%s\' cannot be handled for this query type", get_subsys_name(sub));
			}	
		}	
	}	

	if (subsys_set.size() > GY_ARRAY_SIZE(psubsys_arr_)) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Criteria Error : Max number of different subsystems limit %lu breached : %lu", 
					GY_ARRAY_SIZE(psubsys_arr_), subsys_set.size());
	}

	for (SUBSYS_CLASS_E sub : subsys_set) {
		psubsys_arr_[nsubsys_++] = sub;
	}	

	if (is_multihost) {
		validate_multihost_criteria();
	}	
	
}
	

} // namespace gyeeta 

