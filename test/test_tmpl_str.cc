//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_common_inc.h"
#include			"gy_json_field_maps.h"

#include			<iostream>

using namespace gyeeta;

class TALERT_TMPL_STRING
{
public :
	struct Offsets
	{
		uint16_t		start_		{0};
		uint16_t		end_		{0};
		bool			is_alertdata_	{false};

		Offsets(uint16_t start, uint16_t end, bool is_alertdata) noexcept
			: start_(start), end_(end), is_alertdata_(is_alertdata)
		{}

		Offsets() noexcept	= default;
	};

	std::unique_ptr<char[]>		str_;
	std::vector<Offsets>		toffsets_;
	uint32_t			lenstr_		{0};

	TALERT_TMPL_STRING(const char *pstr, uint32_t sz);	
};	

TALERT_TMPL_STRING::TALERT_TMPL_STRING(const char *pstr, uint32_t sz)
	: lenstr_(sz)
{
	if (sz == 0) {
		return;
	}	

	if (sz > 8 * 1024) {
		GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Template String \'%s\' Length Too large : Max 8KB allowed", CHAR_BUF<128>(pstr, sz).get());
	}

	str_ = std::make_unique<char []>(sz + 1);
	std::memcpy(str_.get(), pstr, sz);
	*(str_.get() + sz) = 0;

	char			*pstart = str_.get(), *pend = pstart + sz, *ptmp = pstart, *ptmp2, *pfield, *pfend;
	const JSON_DB_MAPPING 	*pcolmap = json_db_svcstate_arr;
	uint32_t 		nmap_fields = GY_ARRAY_SIZE(json_db_svcstate_arr);
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
		ptmp[1] = ' ';
	
		ptmp += 2;

		pfield = ptmp;

		ptmp2 = (char *)memmem(ptmp, pend - ptmp, "}}", 2);

		if (!ptmp2) {
			break;
		}	
		
		pfend = ptmp2 - 1;

		ptmp2[0] = ' ';
		ptmp2[1] = ' ';

		if (pfield + 3 < pfend) {
			bool			is_alertdata;

			while (pfield + 3 < pfend && is_space_tab(*pfield)) pfield++;

			ptmp = pfield;

			while (ptmp < pfend && !is_space_tab(*pfield)) ptmp++;
			
			pfend = ptmp;

			if (pfield + 3 < pfend) {
				if (get_jsoncrc_mapping(pfield, pfend - pfield, pcolmap, nmap_fields)) {
					is_alertdata = true;
				}	
				else if (get_jsoncrc_mapping(pfield, pfend - pfield, json_db_alerts_arr, nalert_fields)) {
					is_alertdata = false;
				}	
				else {
					goto next;
				}

				toffsets_.emplace_back(pfield - pstart, pfend - pstart, is_alertdata);
			}	
		}

next :
		ptmp = ptmp2 + 2;

	} while (ptmp + 3 < pend);
}	


int main()
{
	std::string		input;

	IRPRINT("\n\n");
	INFOPRINT("Enter a Template expression to parse : \n\tFor e.g. \'Alert for Slow {{ name }} Response : p95 response {{ p95resp }} > 100 msec over 4 min with p95 QPS > 50\' : ");

	while (std::getline(std::cin, input)) {
		try {
			INFOPRINTCOLOR(GY_COLOR_CYAN, "Parsing expr : \'%s\' : \n\n", input.data());
			
			TALERT_TMPL_STRING(input.data(), input.size());
		}
		GY_CATCH_EXPRESSION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while parsing criteria : %s\n\n", GY_GET_EXCEPT_STRING);
		);

		INFOPRINT("Enter the next Template expression or press <Ctrl-C> to exit... : ");
	}	
}

