//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later


#include			"gy_rapidjson.h"
#include			"gy_stack_container.h"

using namespace gyeeta;

static constexpr const char		filter1[] = " ({ a > b }) ";
static constexpr const char		filjson1[] = R"(
{
    "data": "a > b",
    "hash": "721a26d4bc734019"
}
)";

static constexpr const char		filter2[] = " ({ a > 10 }) and ({ c > 3 })";
static constexpr const char		filjson2[] = R"(
{
    "children": [
        {
            "data": "c > 3",
            "hash": "c9f246cb32bec464"
        },
        {
            "data": "a > 10",
            "hash": "98534f0c2e308188"
        }
    ],
    "oper": "AND"
}
)";


static constexpr const char	filter3[] =  "( ( ({ a = 1 }) and ({ b > 4 }) ) or ( ({ c > 3 }) and ( ({ b = 2 }) or ({ d = 2 }) ) ) ) ";
static constexpr const char 	filjson3[] = R"(
{
    "children": [
        {
            "children": [
                {
                    "data": "c > 3",
                    "hash": "c9f246cb32bec464"
                },
                {
                    "data": "b = 2",
                    "hash": "4037375406929e1b"
                }
            ],
            "oper": "AND"
        },
        {
            "children": [
                {
                    "data": "c > 3",
                    "hash": "c9f246cb32bec464"
                },
                {
                    "data": "d = 2",
                    "hash": "f35463e2807f2090"
                }
            ],
            "oper": "AND"
        },
        {
            "children": [
                {
                    "data": "b > 4",
                    "hash": "36010abcdcdb8f07"
                },
                {
                    "data": "a = 1",
                    "hash": "fd352b68bf833912"
                }
            ],
            "oper": "AND"
        }
    ],
    "oper": "OR"
}

)";

static constexpr const char  	filter4[] = " ( ({ a > 0 }) or ( ({ b > 1 }) and ( ({ c > 2 }) or ( ({ d > 2 }) and ( ({ e > 3 }) or ( ({ f > 4 }) and ({ g > 5}) )) ) )))";
static constexpr const char	filjson4[] = R"(
{
    "children": [
        {
            "children": [
                {
                    "data": "d > 2",
                    "hash": "fff5ccbc1e00b55a"
                },
                {
                    "data": "b > 1",
                    "hash": "4da94b5d489fc01f"
                },
                {
                    "data": "f > 4",
                    "hash": "c4e213bc99b142a4"
                },
                {
                    "data": "g > 5",
                    "hash": "eaba98f03866ca2e"
                }
            ],
            "oper": "AND"
        },
        {
            "children": [
                {
                    "data": "e > 3",
                    "hash": "2558e1034f0e33a3"
                },
                {
                    "data": "b > 1",
                    "hash": "4da94b5d489fc01f"
                },
                {
                    "data": "d > 2",
                    "hash": "fff5ccbc1e00b55a"
                }
            ],
            "oper": "AND"
        },
        {
            "children": [
                {
                    "data": "b > 1",
                    "hash": "4da94b5d489fc01f"
                },
                {
                    "data": "c > 2",
                    "hash": "980027be09e9b6b1"
                }
            ],
            "oper": "AND"
        },
        {
            "data": "a > 0",
            "hash": "3ee692a199c12554"
        }
    ],
    "oper": "OR"
}

)";

struct teststruct
{
	int				a, b, c, d, e, f, g;

	static constexpr uint32_t 	crc_arr[] = 
	{
		gy_crc32_constexpr("a"), gy_crc32_constexpr("b"), gy_crc32_constexpr("c"),
		gy_crc32_constexpr("d"), gy_crc32_constexpr("e"), gy_crc32_constexpr("f"),
		gy_crc32_constexpr("g"),
	};	

	teststruct() noexcept
	{
		gy_safe_memset(this);
	}

	bool filter_eval(const char * __restrict__ paramstr, const char * __restrict__ operstr, const char * __restrict__  valstr) const
	{
		uint32_t		crcpar = gy_crc32(paramstr, strlen(paramstr));
		int			param, value;

		switch (crcpar) {
		
		case crc_arr[0] :	param = a; break;
			
		case crc_arr[1] :	param = b; break;
			
		case crc_arr[2] :	param = c; break;
			
		case crc_arr[3] :	param = d; break;
			
		case crc_arr[4] :	param = e; break;
			
		case crc_arr[5] :	param = f; break;
			
		case crc_arr[6] :	param = g; break;
			
		default		:	
			GY_THROW_EXCEPTION("Invalid Filter Criterion : Parameter Field %s not valid", paramstr);
		}	

		if (!string_to_number(valstr, value)) {
			// Check if the value refers to a member

			switch (gy_crc32(valstr, strlen(valstr))) {
			
			case crc_arr[0] :	value = a; break;
				
			case crc_arr[1] :	value = b; break;
				
			case crc_arr[2] :	value = c; break;
				
			case crc_arr[3] :	value = d; break;
				
			case crc_arr[4] :	value = e; break;
				
			case crc_arr[5] :	value = f; break;
				
			case crc_arr[6] :	value = g; break;
				
			default		:
				GY_THROW_EXCEPTION("Invalid Filter Criterion : Value Field %s not valid : Must be a constant value or a valid field", valstr);
			}	
		}	
		
		switch (*operstr) {
		
		case '=' :	
			return param == value;

		case '!' :	
			if (operstr[1] != '=') break;
			return param != value;

		case '<' :	
			if (operstr[1] == '=') return param <= value;
			if (operstr[1] != 0) break;
			return param < value;

		case '>' :	
			if (operstr[1] == '=') return param >= value;
			if (operstr[1] != 0) break;
			return param > value;

		default :	
			break;
		}	

		GY_THROW_EXCEPTION("Invalid Filter Criterion : Numerical Operator Field \'%s\' not valid : Must be one of <, <=, >, >=, =, != only", operstr);
	}	

	void print() noexcept
	{
		IRPRINT("\n\n");
		INFOPRINT("teststruct : a = %d, b = %d, c = %d, d = %d, e = %d, f = %d, g = %d\n\n", a, b, c, d, e, f, g);
	}	
};	


template <typename T>
bool eval_one_crit(const T & tdata, const char * pone, size_t szone)
{
	char			buf1[4096];
	char			*ptmp, *pend;
	const char		*paramstr, *operstr, *valstr;			

	if (szone >= sizeof(buf1)) {
		GY_THROW_EXCEPTION("Invalid One Criterion Length : Too large %lu : Max allowed is %lu", szone, sizeof(buf1) - 1);
	}

	std::memcpy(buf1, pone, szone);
	buf1[szone] = 0;
	
	ptmp = buf1;
	pend = buf1 + szone;

	while (ptmp < pend && (*ptmp == ' ' || *ptmp == '\t')) ptmp++;

	if (ptmp == pend) {
		GY_THROW_EXCEPTION("Invalid Filter Criterion format : %s : Must be of type : <Param> <Operator> <Value>", pone);
	}	

	paramstr = ptmp++;

	while (ptmp < pend && (*ptmp != ' ' && *ptmp != '\t')) ptmp++;

	if (ptmp == pend) {
		GY_THROW_EXCEPTION("Invalid Filter Criterion format : %s : Must be of type : <Param> <Operator> <Value>", pone);
	}	

	*ptmp++ = 0;

	while (ptmp < pend && (*ptmp == ' ' || *ptmp == '\t')) ptmp++;

	if (ptmp == pend) {
		GY_THROW_EXCEPTION("Invalid Filter Criterion format : %s : Missing Operator : Must be of type : <Param> <Operator> <Value>", pone);
	}	

	operstr = ptmp++;

	while (ptmp < pend && (*ptmp != ' ' && *ptmp != '\t')) ptmp++;

	if (ptmp == pend) {
		GY_THROW_EXCEPTION("Invalid Filter Criterion format : %s : Must be of type : <Param> <Operator> <Value>", pone);
	}	

	*ptmp++ = 0;

	while (ptmp < pend && (*ptmp == ' ' || *ptmp == '\t')) ptmp++;

	if (ptmp == pend) {
		GY_THROW_EXCEPTION("Invalid Filter Criterion format : %s : Missing Value : Must be of type : <Param> <Operator> <Value>", pone);
	}	

	valstr = ptmp;

	return tdata.filter_eval(paramstr, operstr, valstr);
}	

template <typename T, typename Jobj, typename Map>
bool eval_one_obj(const T & tdata, const Jobj & obj, Map & fmap) 
{
	auto 			hashit = obj.FindMember("hash");
	
	if ((hashit == obj.MemberEnd()) || (false == hashit->value.IsString())) {
		GY_THROW_EXCEPTION("[Internal Error]: Invalid Interpreted Filter JSON : hash field not valid");
	}	

	uint64_t		fhash;
	int			ret;
	bool			bret;

	bret = string_to_number(hashit->value.GetString(), fhash, nullptr, 16);

	if (!bret) {
		GY_THROW_EXCEPTION("[Internal Error]: Invalid Interpreted Filter JSON : hash field value not valid");
	}	

	auto 			[sit, success] = fmap.try_emplace(fhash, false);
	
	if (success == false) {
		bret = sit->second;

		if (bret == false) {
			INFOPRINTCOLOR(GY_COLOR_LIGHT_RED, "Filter Failed for criterion based on hash map for hash 0x%016lx\n", fhash);
		}	
		else {
			INFOPRINTCOLOR(GY_COLOR_GREEN, "Filter Success for criterion based on hash map for hash 0x%016lx\n", fhash);
		}

		return bret;
	}	

	auto 			datait = obj.FindMember("data");
	
	if ((datait == obj.MemberEnd()) || (false == datait->value.IsString())) {
		GY_THROW_EXCEPTION("[Internal Error]: Invalid Interpreted Filter JSON : data field not valid");
	}	

	bret = eval_one_crit(tdata, datait->value.GetString(), datait->value.GetStringLength());

	sit->second = bret;

	if (bret == false) {
		INFOPRINTCOLOR(GY_COLOR_LIGHT_RED, "Filter Failed for criterion \'%s\' (hash 0x%016lx)\n", datait->value.GetString(), fhash);
	}	
	else {
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Filter Success for criterion \'%s\' (hash 0x%016lx)\n", datait->value.GetString(), fhash);
	}

	return bret;
};	


template <typename T>
bool eval_filter(const T & tdata, const char *pfilter, size_t szfilter)
{
	using Stackmap 			= GY_STACK_HASH_MAP<uint64_t, bool, 1024>;
	using Arena			= Stackmap::allocator_type::arena_type;

	Arena				arena;
	Stackmap			fmap(arena);

	JSON_DOCUMENT<2048, 2048>	jdoc;
	auto				& doc = jdoc.get_doc();
	int				nchecked = 0;
	bool				first_oper_or = true, result = false, iscomplete = false;

	// Parse situ if not readonly
	if (doc.Parse(pfilter, szfilter).HasParseError()) {
		GY_THROW_EXCEPTION("Invalid json : Error at offset %lu : Error is \'%s\'", doc.GetErrorOffset(), rapidjson::GetParseError_En(doc.GetParseError()));
	}	

	auto operit = doc.FindMember("oper");
	if (operit != doc.MemberEnd()) {
		if (false == operit->value.IsString()) {
			GY_THROW_EXCEPTION("Invalid Filter JSON : oper field not of string type");
		}	

		if (strcmp("OR", operit->value.GetString())) {
			first_oper_or = false;
		}	
	}	


	auto childit1 = doc.FindMember("children"); 
	if (childit1 != doc.MemberEnd()) {
		if (false == childit1->value.IsArray()) {
			GY_THROW_EXCEPTION("Invalid Filter JSON : children field not of array type");
		}	

		uint32_t 		f = 0;

		for (; f < childit1->value.Size(); f++) {

			if (false == childit1->value[f].IsObject()) {
				GY_THROW_EXCEPTION("[Internal Error]: Invalid Interpreted Filter JSON : children array element not of object type");
			}	

			const auto 		& childobj1 = childit1->value[f].GetObject();
			bool			bret;

			auto childit2 = childobj1.FindMember("children"); 

			if (childit2 != childobj1.MemberEnd()) {
				if (false == childit2->value.IsArray()) {
					GY_THROW_EXCEPTION("[Internal Error]: Invalid Filter JSON : children field level 2 not of array type");
				}

				uint32_t 		c = 0;

				for (; c < childit2->value.Size(); c++) {

					if (false == childit2->value[c].IsObject()) {
						GY_THROW_EXCEPTION("[Internal Error]: Invalid Interpreted Filter JSON : children array 2 element not of object type");
					}	

					const auto 		& childobj2 = childit2->value[c].GetObject();

					auto soperit = childobj2.FindMember("oper");
					if (soperit != childobj2.MemberEnd()) {
						if (false == soperit->value.IsString()) {
							GY_THROW_EXCEPTION("Invalid Filter JSON : oper 2 field not of string type");
						}	

						if (strcmp("AND", soperit->value.GetString())) {
							GY_THROW_EXCEPTION("[Internal Error]: Invalid Filter JSON Parsing : oper 2 not of AND type");
						}	
					}	

					auto 			childit3 = childobj2.FindMember("children"); 

					if (childit3 != childobj2.MemberEnd()) {
						GY_THROW_EXCEPTION("Invalid Filter JSON : Filter is too deeply nested. Not currently supported. Please simplify the criteria");
					}

					bret = eval_one_obj(tdata, childobj2, fmap);
					nchecked++;

					if (bret == false) {
						break;
					}	
				}	

				if (c == childit2->value.Size() && c > 0) {
					if (first_oper_or == true) {
						INFOPRINTCOLOR(GY_COLOR_BLUE, "Skipping rest of filter checks as one complete criterion success seen for children object #%lu...\n", f);
						result = true;
						break;
					}	
				}
			}
			else {
				bret = eval_one_obj(tdata, childobj1, fmap);
				nchecked++;

				if (bret == false) {
					if (first_oper_or == false) {
						INFOPRINTCOLOR(GY_COLOR_BLUE, "Skipping rest of filter checks as one criterion failure seen for children object #%lu...\n", f);
						result = false;

						break;
					}
				}	
				else if (first_oper_or == true) {
					INFOPRINTCOLOR(GY_COLOR_BLUE, "Skipping rest of filter checks as one criterion success seen for children object #%lu...\n", f);
					result = true;
					break;
				}	
			}	
		}	

		if (f == childit1->value.Size()) {
			if (first_oper_or == true) {
				result = false;
			}
			else {
				result = true;
			}
		}
	}	
	else {
		bool		bret = eval_one_obj(tdata, doc, fmap);
		nchecked++;

		result = bret;
	}	

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Result of Filter Evaluation : Filter %s : # Conditions checked %lu\n\n", result ? "Passed" : "Failed", nchecked);

	return result;
}	


int main(int argc, char *argv[])
{
	if (argc < 2) {
		IRPRINT("\n\nUsage : %s <Value of a> <b> <c> <d> <e> <f> <g> <Optional filter json strings...>\n\ne.g. : %s 11 2 3 3 3 5 4\n\n", argv[0], argv[0]);
		return -1;
	}	

	int		sarr[sizeof(teststruct)/sizeof(int) + 1] {};
	teststruct	s;

	for (int i = 1; i < argc && (unsigned)i <= GY_ARRAY_SIZE(sarr); ++i) {
		sarr[i - 1] = atoi(argv[i]); 
	}	

	std::memcpy((void *)&s, sarr, sizeof(s));
	
	s.print();

	try {
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Starting Filter parse for filter string : \'%s\'\n", filter1);

		eval_filter(s, filjson1, sizeof(filjson1) - 1);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while evaluating filter \'%s\' : %s\n", filter1, GY_GET_EXCEPT_STRING);
	);
	
	try {
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Starting Filter parse for filter string : \'%s\'\n", filter2);

		eval_filter(s, filjson2, sizeof(filjson2) - 1);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while evaluating filter \'%s\' : %s\n", filter2, GY_GET_EXCEPT_STRING);
	);

	try {
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Starting Filter parse for filter string : \'%s\'\n", filter3);

		eval_filter(s, filjson3, sizeof(filjson3) - 1);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while evaluating filter \'%s\' : %s\n", filter3, GY_GET_EXCEPT_STRING);
	);

	try {
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Starting Filter parse for filter string : \'%s\'\n", filter4);

		eval_filter(s, filjson4, sizeof(filjson4) - 1);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while evaluating filter \'%s\' : %s\n", filter4, GY_GET_EXCEPT_STRING);
	);

	for (int i = 8; i < argc; ++i) {

		try {
			IRPRINT("\n\n");
			INFOPRINTCOLOR(GY_COLOR_CYAN, "Starting Filter parse for external filter string : \'%s\'\n", argv[i]);

			eval_filter(s, argv[i], strlen(argv[i]));
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Exception caught while evaluating filter \'%s\' : %s\n", argv[i], GY_GET_EXCEPT_STRING);
		);
	}	

	return 0;
}	
