//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_common_inc.h"
#include			"gy_boolparse.h"
#include			"gy_json_field_maps.h"
#include			"gy_stack_container.h"

#include			<set>
#include 			"boolstuff/BoolExprParser.h"

namespace gyeeta {

using namespace boolstuff;

/*
 * We first transform the input string such as :
 * 
 *	e.g.	( ( { host substr 'prod' } or { cluster like 'cl[5-9].*' } ) and { svcid = '8e4343f0702963a4' } and ( { p95resp5s < resp5s } or { kbin15s + kbout15s > 1 } ) )
 *
 * 	to the format : ( ( 0 | 1 ) & 2 & ( 3 | 4 ) ) and then pass it to the Boolstuff lib
 *
 */
GY_BOOLPARSE::GY_BOOLPARSE(const char *pinput, size_t szexpr)
{
	if (!pinput || !szexpr) return;

	if (szexpr > 8 * 1024) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Max Filter Expression length exceeded Max is 8192 (8KB) : Please reduce Filter Expression : Input Filter is of length %lu", szexpr);
	}	

	auto 			[pstart, sz] = get_trim_str(pinput, szexpr);
	
	if (!sz) {
		return;
	}	

	STRING_BUFFER<1024>	strbuf;

	replace_expr_criteria(strbuf, pstart, sz);

	if (mapvec_.size() <= 1) {
		ncritgroups_ = 1;
		is_l1_and_ = true;
		nl1_crit_ = 1;
		max1crit_ = 1;
		total_crit_ = 1;

		mapvec_.clear();
		return;
	}

	if (strbuf.is_overflow()) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criteria : Max limit of criteria in string buffer limit breached : Please reduce the Filter");
	}	

	try {
		using 				BoolUniq = std::unique_ptr<boolstuff::BoolExpr<std::string>>;
		using 				ExprVec = INLINE_STACK_VECTOR<const boolstuff::BoolExpr<std::string> *, MAX_CRITERIA_GROUPS * sizeof(void *) + 24>;

		boolstuff::BoolExprParser	parser;
		BoolUniq			pdnftree;
		BoolExpr<std::string> 		*pexpr = nullptr, *pdnf = nullptr;

		pexpr = parser.parse(strbuf.buffer(), strbuf.length());

		if (!pexpr) {
			GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Query Criterion : Invalid Filter Criteria : Could not parse Boolean expression");
		}	

		pdnf = pexpr->getDisjunctiveNormalForm(pexpr);

		pdnftree.reset(pdnf);

		ExprVec				exprvec;

		pdnf->getDNFTermRoots(std::inserter(exprvec, exprvec.end()));
		
		ncritgroups_ = exprvec.size();

		if (ncritgroups_ > MAX_CRITERIA_GROUPS) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Criteria : Max limit of criteria groups %lu limit breached (%u) : Please reduce the Filter", 
							MAX_CRITERIA_GROUPS, ncritgroups_);
		}	

		idvec_.reserve(ncritgroups_);

		for (uint32_t grpnum = 0; grpnum < ncritgroups_; ++grpnum) {
			const BoolExpr<std::string> 	*pterm = exprvec[grpnum];
			std::set<std::string> 		positives, negatives; 		/* Currently NOT Operator is not supported : so ignore negatives ...*/
			uint32_t			id, nupd = 0, ncrit;
			bool				bret;	

			if (!pterm) {
				GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Query Criteria : Null Criteria Group Number %u tree Variable", grpnum);
			}	
			
			pterm->getTreeVariables(positives, negatives);

			ncrit = positives.size();

			if (ncrit > MAX_ONE_GROUP_CRITERIA) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criteria : Max limit of criteria within a group limit (%lu) breached : %u : Please reduce the Filter", 
						MAX_ONE_GROUP_CRITERIA, ncrit);
			}	

			if (negatives.size() > 0) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Criteria : NOT (!) Operator not currently supported. Please directly use the negated comparator instead");
			}	

			auto 				& vec = idvec_.emplace_back();

			vec.reserve(ncrit);

			total_crit_ += ncrit;

			if (total_crit_ > MAX_QUERY_CRITERIA) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criteria : Max limit of criteria (Disjunctive Normalized) for a query limit (%lu) breached : %u : Please reduce the Filter", 
						MAX_QUERY_CRITERIA, total_crit_);
			}	

			if (max1crit_ < ncrit) {
				max1crit_ = ncrit;
			}	

			if (ncritgroups_ > 1) {
				if (ncrit > 1) {
					nl2groups_++;
				}	
				else {
					nl1_crit_ += ncrit;
				}	
			}	

			for (const auto & str : positives) {
				bret = string_to_number(str.data(), id, nullptr, 10);

				if (!bret || id >= mapvec_.size()) {
					GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Query Criteria : Criteria returned from bool parser invalid : %s", str.data());
				}
				
				vec.push_back(id);
			}	
		}	

		if (ncritgroups_ == 1) {
			nl1_crit_ = total_crit_;
			is_l1_and_ = true;
		}	
	}
	catch (BoolExprParser::Error &err) {
		switch (err.code) {
		
		case 0 :	// GARBAGE_AT_END
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Query Criterion : Invalid/extra characters at end of filter : Parsed criteria of the form \'%s\'", strbuf.buffer());

		case 1 :	// RUNAWAY_PARENTHESIS
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Query Criterion : Mismatched parenthesis seen : Parsed criteria of the form \'%s\'", strbuf.buffer());

		case 2 :
		default :	// IDENTIFIER_EXPECTED
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Query Criterion : Missing criterion at the end of filter or extra comparators seen : Parsed criteria of the form \'%s\'", 
					strbuf.buffer());
		}	
	}	
	catch(...) {
		throw;
	}	
}	

void GY_BOOLPARSE::replace_expr_criteria(STR_WR_BUF & strbuf, const char *pinput, size_t sz)
{
	using 				ExprMap = INLINE_STACK_HASH_MAP<uint32_t, uint32_t, 2048, GY_JHASHER<uint32_t>>;

	ExprMap				expmap;
	const char			*ptmp = pinput, *pstart = pinput, *pend = pinput + sz, *pnxtwr = pinput, *ptmp2;
	int				noper = 0;
	char				c, c2, c3, c4;
	bool				reqstart = true, reqend = false;

	const auto is_space_paren = [&](char c) noexcept
	{
		if (c == ' ' || c == '\t' || c == ')') {
			pnxtwr = ptmp;
			strbuf << c;

			return true;
		}	

		return false;
	};

	ptmp2 = (const char *)memchr(pstart, '{', pend - ptmp);

	if (!ptmp2) {
		// Check if AND/OR missed due to missing braces

		ptmp++;

		while (ptmp + 4 < pend) {
			c = gy_tolower_ascii(*ptmp);

			if (c == '\'') {
				ptmp++;

				while (ptmp + 1 < pend && *ptmp != '\'') ptmp++;
			}	
			else if (c == 'a') {
				if (is_space_tab(ptmp[-1]) && (gy_tolower_ascii(ptmp[1]) == 'n') && (gy_tolower_ascii(ptmp[2]) == 'd') && is_space_tab(ptmp[3])) {

					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Criteria : 2 or more criteria not separated by braces {} as AND seen : \'%s\'",
											CHAR_BUF<128>(ptmp, pend - ptmp).get()); 
				}	
			}	
			else if (c == 'o') {
				if (is_space_tab(ptmp[-1]) && (gy_tolower_ascii(ptmp[1]) == 'r') && is_space_tab(ptmp[2])) {

					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Criteria : 2 or more criteria not separated by braces {} as OR seen : \'%s\'",
											CHAR_BUF<128>(ptmp, pend - ptmp).get()); 
				}	
			}	

			ptmp++;
		}	

		// Ok checked
		firstcrit_ = std::string_view(pinput, sz);
		return; 
	}	

	while (ptmp < ptmp2) {
		c = *ptmp;

		if (c == ' ' || c == '\t' || c == '(') {
			ptmp++;
		}
		else {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Query Criteria : criterion must start with a brace { : instead \'%s\' seen", 
									CHAR_BUF<128>(pstart, ptmp - pstart + 1).get()); 
		}	
	}	

	while (ptmp + 1 < pend) {		
		if (*ptmp != '{') {
			ptmp = (const char *)memchr(ptmp, '{', pend - ptmp);
		}

		if (!ptmp) {
			break;
		}
		else if (ptmp + 2 >= pend) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Query Criterion : Extra empty brace { seen at end of expression");
		}	


		reqstart = false;
		reqend = true;
		
		if (pnxtwr < ptmp) {
			strbuf.append(pnxtwr, ptmp - pnxtwr);
		}	

		pnxtwr = ptmp + 1;
		
		do {
			++ptmp;
			c = *ptmp;

			if (c == '}') {
				reqstart = false;

				auto 			[ptxt, sztxt] = get_trim_str(pnxtwr, ptmp - pnxtwr);

				if (sztxt < 5) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Query Criterion : Too small or empty criterion seen \'%s\' : Must be of format <Field> <Operator> <Value>", 
						CHAR_BUF<128>(pnxtwr, ptmp - pnxtwr + 1).get()); 
				}	
				
				auto 			[eit, etrue] = expmap.try_emplace(fnv1_hash(ptxt, sztxt), (uint32_t)mapvec_.size());

				if (etrue) {
					strbuf << mapvec_.size();
					mapvec_.emplace_back(ptxt, sztxt);
				}
				else {
					strbuf << eit->second;
				}	

				ptmp++;
				pnxtwr = ptmp;

				reqend = false;
				break;
			}	
			else if (c == '\'') {
				ptmp++;

				while (ptmp < pend && *ptmp != '\'') {
					ptmp++;
				}	

				if (ptmp == pend) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Query Criterion : Unterminated string character seen \'%s\'", 
											CHAR_BUF<128>(pnxtwr, ptmp - pnxtwr + 1).get()); 
				}	
			}	
			else if (c == '{') {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Query Criterion : invalid/extra Character \'{\' seen for string \'%s\'", 
										CHAR_BUF<128>(pnxtwr, ptmp - pnxtwr + 1).get()); 
			}	
		} while (ptmp < pend);	

		if ((ptmp == pend) && reqend) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Query Criterion : Unterminated criterion : end of criterion char \'}\' not seen \'%s\'", 
									CHAR_BUF<128>(pnxtwr, ptmp - pnxtwr + 1).get()); 

		}	

		while (ptmp + 1 < pend && is_space_paren(*ptmp)) ptmp++;

		if (ptmp + 5 > pend) {
			break;
		}	

		c 	= gy_tolower_ascii(*ptmp);
		c2 	= gy_tolower_ascii(ptmp[1]);
		c3 	= gy_tolower_ascii(ptmp[2]);
		c4 	= gy_tolower_ascii(ptmp[3]);

		if (c == 'a') {
			if (c2 != 'n' || c3 != 'd' || !is_space_tab(c4)) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Query Criterion : invalid logical operator seen \'%c%c%c\' expecting either \'and\' or \'or\'", 
									c, c2, c3);
			}	

			strbuf << " & "sv;
			ptmp += 4;
		}	
		else if (c == 'o' && c2 == 'r' && is_space_tab(c3)) {
			strbuf << " | "sv;
			ptmp += 3;
		}
		else {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Query Criterion : invalid logical operator seen \'%s\' expecting either \'and\' or \'or\'", 
				CHAR_BUF<128>(ptmp, pend - ptmp).get());
		}	

		while (ptmp + 1 < pend && is_space_tab(*ptmp)) ptmp++;

		if (ptmp + 1 >= pend) {
			break;
		}

		pnxtwr = ptmp;
		noper++;

		while (ptmp + 1 < pend && (*ptmp == '(' || is_space_tab(*ptmp))) ptmp++;

		if (ptmp + 1 >= pend) {
			break;
		}

		if (*ptmp != '{') {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Query Criterion : Invalid character seen for start of new Criteria \'%s\' expecting a brace { ", 
									CHAR_BUF<128>(ptmp - 1, pend - ptmp + 1).get());
		}	

		if (pnxtwr < ptmp) {
			strbuf.append(pnxtwr, ptmp - pnxtwr);
			pnxtwr = ptmp + 1;
		}	
	}

	if (mapvec_.size()) {
		if (mapvec_.size() == 1) {
			firstcrit_ = mapvec_[0];
		}	
		else if (pnxtwr < pend) {
			strbuf.append(pnxtwr, pend - pnxtwr);
		}	
	}
	else {
		firstcrit_ = std::string_view(pinput, sz);
	}	
}	


uint32_t GY_BOOLPARSE::get_group_criteria(size_t grpnum, std::string_view critarr[], size_t maxelem) const
{
	if (maxelem == 0) return 0;

	if (grpnum >= idvec_.size()) {

		if (grpnum == 0 && false == firstcrit_.empty()) {
			critarr[0] = std::string_view(firstcrit_);
			return 1;
		}	

		GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "Query Criteria : Invalid Criteria Group Number %lu requested : Max available %lu", grpnum, idvec_.size());
	}

	const auto 			& vec = idvec_[grpnum];
	uint32_t			nupd = 0;

	if (vec.size() > maxelem) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid Criteria : Max limit of criteria within a group limit (%lu) breached : %lu : Please reduce the Filter", 
								maxelem, vec.size());
	}

	for (const uint32_t id : vec) {
		critarr[nupd++] = std::string_view(mapvec_[id]);
	}	

	return nupd;
}


} // namespace gyeeta

