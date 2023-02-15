//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later


#pragma				once

#include			"gy_common_inc.h"
#include			"gy_misc.h"
#include			"gy_json_field_maps.h"
#include			"gy_stack_pool.h"
#include			"gy_stack_container.h"
#include			"gy_rapidjson.h"
#include			"gy_postgres.h"
#include			"gy_comm_proto.h"

#include 			"re2/re2.h"

namespace gyeeta {

enum CRIT_RET_E : uint8_t
{
	CRIT_FAIL		= 0,
	CRIT_PASS		= 1,
	CRIT_SKIP		= 2,
};	


enum COMPARATORS_E : uint8_t
{
	COMP_EQ			= 0,
	COMP_NEQ,
	COMP_LT,
	COMP_LE,
	COMP_GT,
	COMP_GE,
	COMP_BIT2,		// (num & 3) == 3 (Last 2 bits set : Internal comparatator)
	COMP_BIT3,		// (num & 7) == 7 (Last 3 bits set : Internal comparatator)
	COMP_SUBSTR,
	COMP_NOTSUBSTR,
	COMP_LIKE,
	COMP_NOTLIKE,
	COMP_IN,
	COMP_NOTIN,

	COMP_MAX,
};	

struct COMPARE_MAPPING
{
	const char		*compstr;
	COMPARATORS_E		compval;
	uint32_t		jsoncrc;
	bool			isvalid[std::max<uint8_t>(JSON_MAX_TYPE + 1, JSON_EXPR_TYPE)];
};	

static constexpr COMPARE_MAPPING comparator_map[] =
{
	// compstr		compval		jsoncrc				isvalid[JSON_NUMBER]	isvalid[JSON_STRING]	isvalid[JSON_BOOL]	isvalid[JSON_EXPR_TYPE]
	{ "=",			COMP_EQ,	fnv1_consthash("="),		{ true,			true,			true,			true } },
	{ "!=",			COMP_NEQ,	fnv1_consthash("!="),		{ true,			true,			true,			true } },

	{ "<",			COMP_LT,	fnv1_consthash("<"),		{ true,			false,			false,			true } },
	{ "<=",			COMP_LE,	fnv1_consthash("<="),		{ true,			false,			false,			true } },
	{ ">",			COMP_GT,	fnv1_consthash(">"),		{ true,			false,			false,			true } },
	{ ">=",			COMP_GE,	fnv1_consthash(">="),		{ true,			false,			false,			true } },

	{ "bit2",		COMP_BIT2,	fnv1_consthash("bit2"),		{ true,			false,			false,			false } },
	{ "bit3",		COMP_BIT3,	fnv1_consthash("bit3"),		{ true,			false,			false,			false } },

	{ "substr",		COMP_SUBSTR,	fnv1_consthash("substr"),	{ false,		true,			false,			false } },
	{ "notsubstr",		COMP_NOTSUBSTR,	fnv1_consthash("notsubstr"),	{ false,		true,			false,			false } },
	{ "like",		COMP_LIKE,	fnv1_consthash("like"),		{ false,		true,			false,			false } },
	{ "notlike",		COMP_NOTLIKE,	fnv1_consthash("notlike"),	{ false,		true,			false,			false } },

	{ "in",			COMP_IN,	fnv1_consthash("in"),		{ true,			true,			false,			false } },
	{ "notin",		COMP_NOTIN,	fnv1_consthash("notin"),	{ true,			true,			false,			false } },

	// Synononymous comparators
	{ "==",			COMP_EQ,	fnv1_consthash("=="),		{ true,			true,			true,			true } },
	{ "~",			COMP_LIKE,	fnv1_consthash("~"),		{ false,		true,			false,			false } },
	{ "~=",			COMP_LIKE,	fnv1_consthash("~="),		{ false,		true,			false,			false } },
	{ "=~",			COMP_LIKE,	fnv1_consthash("=~"),		{ false,		true,			false,			false } },
	{ "!~",			COMP_NOTLIKE,	fnv1_consthash("!~"),		{ false,		true,			false,			false } },
};	


static constexpr char math_operators[] = 
{
	'+',
	'-',
	'*',
	'/',
	'%',
	'&',
	'|',
};	

struct STRING_CRITERION final
{
	char				*str_		{nullptr};
	FREE_FPTR			free_fp_	{nullptr};
	uint32_t			len_		{0};
	uint32_t			maxlen_		{0};

	STRING_CRITERION() noexcept			= default;

	STRING_CRITERION(const char *str, uint32_t len, EXT_POOL_ALLOC *pextpool = nullptr)
	{
		str_		= (char *)EXT_POOL_ALLOC::opt_safe_malloc(pextpool, len + 4 + 1, free_fp_, maxlen_);

		std::memcpy(str_, str, len);
		str_[len]	= 0;
		len_		= len;
	}	

	~STRING_CRITERION() noexcept
	{
		destroy();
	}

	void destroy() noexcept
	{
		if (str_) {
			if (free_fp_) {
				(*free_fp_)(str_);
			}

			str_ = nullptr;
		}	
	}

	STRING_CRITERION(const STRING_CRITERION &)		= delete;
	STRING_CRITERION & operator= (const STRING_CRITERION &)	= delete;

	STRING_CRITERION(STRING_CRITERION && other) noexcept
		: str_(std::exchange(other.str_, nullptr)), free_fp_(other.free_fp_), len_(std::exchange(other.len_, 0)), maxlen_(other.maxlen_)
	{}

	STRING_CRITERION & operator= (STRING_CRITERION && other) noexcept
	{
		if (this != &other) {
			this->~STRING_CRITERION();
			new (this) STRING_CRITERION(std::move(other));
		}

		return *this;
	}	

	const char * get() const noexcept
	{
		return str_;
	}	

	const char * set_ign_case() noexcept
	{
		if (len_ + 4 < maxlen_ && std::memcmp(str_, "(?i)", 4)) {
			std::memmove(str_ + 4, str_, len_ + 1);
			std::memcpy(str_, "(?i)", 4);

			len_ += 4;
		}

		return str_;
	}	

	uint32_t size() const noexcept
	{
		return len_;
	}	

	bool is_valid() const noexcept
	{
		return str_ != nullptr;
	}	

	void set_db_filter(STR_WR_BUF & strbuf, const JSON_DB_MAPPING *pfield) const
	{
		if (false == is_valid()) {
			return;
		}

		if (pfield->oper == nullptr) {
			/*
			 * We do not need to escape this string as single quotes within the string and terminating \\ are not allowed...
			 */

			strbuf.append('\'');
			strbuf.append(str_, len_);
			strbuf.append('\'');
		}
		else {
			std::pair<const char *, size_t>		poper;
			char					tbuf[512];

			poper = pfield->oper(str_, len_, tbuf, sizeof(tbuf)); 

			if (pfield->dbstrtype != DB_STR_NONE) {
				strbuf.append('\'');
			}	

			strbuf.append(poper.first, poper.second);

			if (pfield->dbstrtype != DB_STR_NONE) {
				strbuf.append('\'');
			}	
		}

		if (pfield->dbstrtype != DB_STR_OCHAR) {
			strbuf.appendfmt("::%s", pfield->dbtype);
		}
	}	

	static bool valid_start_string(const char *str) noexcept
	{
		return *str == '\'';
	}	
};

struct NUMBER_CRITERION
{
	union {
		int8_t			int8;
		int16_t			int16;
		int32_t			int32;
		int64_t			int64		{0L};
		double			dbl;
	};

	NUMBER_TYPES_E			type_		{NUM_NAN};
	bool				isvalid_	{false};		

	NUMBER_CRITERION() noexcept			= default;

	NUMBER_CRITERION(int64_t val, NUMBER_TYPES_E type) noexcept
		: int64(val), type_(type), isvalid_(true)
	{}	

	NUMBER_CRITERION(const char *str, NUMBER_TYPES_E type) noexcept
		: type_(type)
	{
		bool			bret = false;
		char			*pendstr = nullptr;

		switch (type) {

		case NUM_INT8 : 	bret = string_to_number(str, int8, &pendstr); break;

		case NUM_INT16 : 	bret = string_to_number(str, int16, &pendstr); break;

		case NUM_INT32 : 	bret = string_to_number(str, int32, &pendstr); break;

		case NUM_INT64 : 	bret = string_to_number(str, int64, &pendstr); break;

		case NUM_DOUBLE :	bret = string_to_number(str, dbl, &pendstr); break;

		default	:		return;

		}	

		if (bret) {
			if (pendstr && *pendstr && (!(*pendstr == ' ' || *pendstr == '\t' || *pendstr == ','))) {
				return;
			}	

			isvalid_ = true;
		}	
	}	

	NUMBER_CRITERION(int8_t val) noexcept : int8(val), type_(NUM_INT8), isvalid_(true) {}

	NUMBER_CRITERION(int16_t val) noexcept : int16(val), type_(NUM_INT16), isvalid_(true) {}

	NUMBER_CRITERION(int32_t val) noexcept : int32(val), type_(NUM_INT32), isvalid_(true) {}

	NUMBER_CRITERION(int64_t val) noexcept : int64(val), type_(NUM_INT64), isvalid_(true) {}

	NUMBER_CRITERION(double val) noexcept : dbl(val), type_(NUM_DOUBLE), isvalid_(true) {}

	int8_t get_int8() const noexcept
	{
		return int8;
	}	

	int16_t get_int16() const noexcept
	{
		return int16;
	}	

	int32_t get_int32() const noexcept
	{
		return int32;
	}	

	int64_t get_int64() const noexcept
	{
		return int64;
	}	

	double get_dbl() const noexcept
	{
		return dbl;
	}	

	template <typename T>
	T get() const noexcept
	{
		if (std::is_same_v<T, int8_t>)		{ return int8; }
		else if (std::is_same_v<T, int16_t>)	{ return int16; }
		else if (std::is_same_v<T, int32_t>)	{ return int32; }
		else if (std::is_same_v<T, int64_t>)	{ return int64; }
		else if (std::is_same_v<T, double>)	{ return dbl; }
		else return T(int64);
	}


	NUMBER_TYPES_E get_type() const noexcept
	{
		return type_;
	}

	bool is_valid() const noexcept
	{
		return isvalid_;
	}	

	bool is_double() const noexcept
	{
		return type_ == NUM_DOUBLE;
	}	

	bool apply_math_oper(char oper, NUMBER_CRITERION num2) noexcept
	{
		double			d2 = 0;
		int64_t			i2 = 0;
		bool			is_i2 = true;

		switch(num2.type_) {
			case NUM_DOUBLE	: 
				is_i2 = false;

				d2 = num2.dbl; 
				if (d2 == 0 && (oper == '/' || oper == '%')) d2 = 1;
				break;

			case NUM_INT8 :
				i2 = num2.int8; 
				break;

			case NUM_INT16 :
				i2 = num2.int16; 
				break;

			case NUM_INT32 :
				i2 = num2.int32; 
				break;

			default		: 
				i2 = num2.int64; 
				break;
		}	

		if (is_i2 && i2 == 0 && (oper == '/' || oper == '%')) i2 = 1;

		switch (type_) {

		case NUM_INT8 : 
			switch (oper) {
			
			case '+' 	:	
				if (!is_i2) int8 += d2;
				else int8 += i2;
				break;

			case '-' 	:	
				if (num2.type_ == NUM_DOUBLE) int8 -= d2;
				else int8 -= i2;
				break;

			case '*' 	:	
				if (!is_i2) int8 *= d2;
				else int8 *= i2;
				break;

			case '/' 	:	
				if (!is_i2) int8 /= d2;
				else int8 /= i2;
				break;

			case '%' 	:	
				if (!is_i2) int8 %= (int64_t)d2;
				else int8 %= i2;
				break;

			case '&' 	:	
				if (!is_i2) int8 &= (int64_t)d2;
				else int8 &= i2;
				break;

			case '|' 	:	
				if (!is_i2) int8 |= (int64_t)d2;
				else int8 |= i2;
				break;

			default 	:
				break;
			}	
			break;


		case NUM_INT16 : 
			switch (oper) {
			
			case '+' 	:	
				if (!is_i2) int16 += d2;
				else int16 += i2;
				break;

			case '-' 	:	
				if (!is_i2) int16 -= d2;
				else int16 -= i2;
				break;

			case '*' 	:	
				if (!is_i2) int16 *= d2;
				else int16 *= i2;
				break;

			case '/' 	:	
				if (!is_i2) int16 /= d2;
				else int16 /= i2;
				break;

			case '%' 	:	
				if (!is_i2) int16 %= (int64_t)d2;
				else int16 %= i2;
				break;

			case '&' 	:	
				if (!is_i2) int16 &= (int64_t)d2;
				else int16 &= i2;
				break;

			case '|' 	:	
				if (!is_i2) int16 |= (int64_t)d2;
				else int16 |= i2;
				break;

			default 	:
				break;
			}	
			break;


		case NUM_INT32 : 
			switch (oper) {
			
			case '+' 	:	
				if (!is_i2) int32 += d2;
				else int32 += i2;
				break;

			case '-' 	:	
				if (!is_i2) int32 -= d2;
				else int32 -= i2;
				break;

			case '*' 	:	
				if (!is_i2) int32 *= d2;
				else int8 *= i2;
				break;

			case '/' 	:	
				if (!is_i2) int32 /= d2;
				else int32 /= i2;
				break;

			case '%' 	:	
				if (!is_i2) int32 %= (int64_t)d2;
				else int32 %= i2;
				break;

			case '&' 	:	
				if (!is_i2) int32 &= (int64_t)d2;
				else int32 &= i2;
				break;

			case '|' 	:	
				if (!is_i2) int32 |= (int64_t)d2;
				else int32 |= i2;
				break;

			default 	:
				break;
			}	
			break;


		case NUM_INT64 :
		default	:
			switch (oper) {
			
			case '+' 	:	
				if (!is_i2) int64 += d2;
				else int64 += i2;
				break;

			case '-' 	:	
				if (!is_i2) int64 -= d2;
				else int64 -= i2;
				break;

			case '*' 	:	
				if (!is_i2) int64 *= d2;
				else int64 *= i2;
				break;

			case '/' 	:	
				if (!is_i2) int64 /= d2;
				else int64 /= i2;
				break;

			case '%' 	:	
				if (!is_i2) int64 %= (int64_t)d2;
				else int64 %= i2;
				break;

			case '&' 	:	
				if (!is_i2) int64 &= (int64_t)d2;
				else int64 &= i2;
				break;

			case '|' 	:	
				if (!is_i2) int64 |= (int64_t)d2;
				else int64 |= i2;
				break;

			default 	:
				break;
			}	
			break;


		case NUM_DOUBLE :
			switch (oper) {
			
			case '+' 	:	
				if (!is_i2) dbl += d2;
				else dbl += i2;
				break;

			case '-' 	:	
				if (!is_i2) dbl -= d2;
				else dbl -= i2;
				break;

			case '*' 	:	
				if (!is_i2) dbl *= d2;
				else dbl *= i2;
				break;

			case '/' 	:	
				if (!is_i2) dbl /= d2;
				else dbl /= i2;
				break;

			case '%' 	:	
			case '&' 	:	
			case '|' 	:	
				return false;
				break;

			default 	:
				break;
			}	
			break;
		}	

		return true;
	}

	void to_string(STR_WR_BUF & strbuf, const JSON_DB_MAPPING *pfield, bool only_data = false) const
	{
		if (false == is_valid()) {
			return;
		}

		if (pfield->oper == nullptr) {
			switch (type_) {

			case NUM_INT8 : 	strbuf.append(int8); break;

			case NUM_INT16 : 	strbuf.append(int16); break;

			case NUM_INT32 : 	strbuf.append(int32); break;

			case NUM_INT64 : 	strbuf.append(int64); break;

			case NUM_DOUBLE :	strbuf.append(dbl); break;

			default	:		strbuf.append(int64); break;
			}	
		}
		else {
			std::pair<const char *, size_t>		poper;

			switch (type_) {

			case NUM_INT8 : 	poper = pfield->oper((void *)(intptr_t)int8, sizeof(int8), nullptr, 0); break;

			case NUM_INT16 : 	poper = pfield->oper((void *)(intptr_t)int16, sizeof(int16), nullptr, 0); break;

			case NUM_INT32 : 	poper = pfield->oper((void *)(intptr_t)int32, sizeof(int32), nullptr, 0); break;

			case NUM_INT64 : 	poper = pfield->oper((void *)(intptr_t)int64, sizeof(int64), nullptr, 0); break;

			case NUM_DOUBLE :	poper = pfield->oper((void *)(intptr_t)dbl, sizeof(dbl), nullptr, 0); break;

			default	:		poper = pfield->oper((void *)(intptr_t)int64, sizeof(int64), nullptr, 0); break;
			}	
			
			if (!only_data && pfield->dbstrtype != DB_STR_NONE) {
				strbuf.append('\'');
			}	

			strbuf.append(poper.first, poper.second);

			if (!only_data && pfield->dbstrtype != DB_STR_NONE) {
				strbuf.append('\'');
			}	
		}

		if (!only_data && type_ != NUM_DOUBLE) {
			strbuf.appendfmt("::%s", pfield->dbtype);
		}	
	}	

	void set_db_filter(STR_WR_BUF & strbuf, const JSON_DB_MAPPING *pfield) const
	{
		to_string(strbuf, pfield, false /* only_data */);
	}

	static bool valid_start_string(const char *str) noexcept
	{
		char		c = *str;

		if (c == '-' || c == '+') {
			c = str[1];
		}

		if (c >= '0' && c <= '9') {
			return true;
		}

		return false;
	}	
};	


struct BOOL_CRITERION
{
	bool				value_		{false};
	bool				isvalid_	{false};		

	BOOL_CRITERION() noexcept			= default;

	BOOL_CRITERION(const char *str) noexcept
	{
		if (0 == memcmp(str, "true", 4)) {
			value_ = true;
			isvalid_ = true;
		}
		else if (0 == memcmp(str, "false", 5)) {
			value_ = false;
			isvalid_ = true;
		}	
	}	

	BOOL_CRITERION(bool value) noexcept
		: value_(value), isvalid_(true)
	{}	

	bool get() const noexcept
	{
		return value_;
	}

	bool is_valid() const noexcept
	{
		return isvalid_;
	}	

	void to_string(STR_WR_BUF & strbuf, const JSON_DB_MAPPING *pfield, bool only_data = false) const
	{
		if (false == is_valid()) {
			return;
		}

		if (pfield->oper == nullptr) {
			strbuf.append(value_);
		}
		else {
			std::pair<const char *, size_t>		poper;

			poper = pfield->oper((void *)(intptr_t)value_, sizeof(value_), nullptr, 0); 

			if (!only_data && pfield->dbstrtype != DB_STR_NONE) {
				strbuf.append('\'');
			}	

			strbuf.append(poper.first, poper.second);

			if (!only_data && pfield->dbstrtype != DB_STR_NONE) {
				strbuf.append('\'');
			}	
		}

		if (!only_data) {
			strbuf.appendfmt("::%s", pfield->dbtype);
		}	
	}	

	void set_db_filter(STR_WR_BUF & strbuf, const JSON_DB_MAPPING *pfield) const
	{
		to_string(strbuf, pfield, false /* only_data */);
	}

	static bool valid_string(const char *str) noexcept
	{
		return (str && ((0 == memcmp(str, "true", 4)) || (0 == memcmp(str, "false", 5))));
	}	

};	

class CRITERION_ONE final
{
public :	
	const char				*subsys_str_		{nullptr};
	const JSON_DB_MAPPING			*pfield1_		{nullptr};

	SUBSYS_CLASS_E				subsys_			{SUBSYS_HOST};
	JSON_TYPES_E				fieldtype_		{JSON_NUMBER};
	COMPARATORS_E				comp_			{COMP_EQ};
	JSON_TYPES_E				valtype_		{JSON_NUMBER};
	bool					is_valid_		{false};
	bool					is_timestamp_sec_	{false};
	bool					is_time_func_		{false};
	char					math_oper_		{0};					
	uint64_t				hash_			{0};

	const JSON_DB_MAPPING			*pfield2_		{nullptr};		// For field math operators
	double					field2_const_		{0};

	std::optional<NUMBER_CRITERION>		numval_;
	std::optional<STRING_CRITERION>		strval_;
	std::optional<BOOL_CRITERION>		boolval_;
	const JSON_DB_MAPPING 			*pexpr_val_		{nullptr};		// For expression variables

	std::optional<RE2>			*pregex_		{nullptr};		// Pointer to std::optional deliberate...
	FREE_FPTR				regex_free_fp_		{nullptr};

	bool					force_double_		{false};
	uint32_t				nin_elems_		{0};			
	NUMBER_CRITERION			*pnumarray_		{nullptr};		// For use with COMP_IN/COMP_NOTIN
	STRING_CRITERION			*pstrarray_		{nullptr};		// For use with COMP_IN/COMP_NOTIN
	FREE_FPTR				arr_free_fp_		{nullptr};

	CRITERION_ONE() noexcept		= default;

	CRITERION_ONE(const char * pone, size_t szone, uint64_t hash, SUBSYS_CLASS_E subsys, const char *subsys_str, const JSON_DB_MAPPING **psubsys_map, uint32_t nmap_fields, \
					EXT_POOL_ALLOC *pextpool = nullptr, bool allocregex = true);

	~CRITERION_ONE() noexcept
	{
		destroy();
	}	

	void destroy() noexcept
	{
		if (pregex_) {
			destruct_dealloc(pregex_, regex_free_fp_);
			pregex_ = nullptr;
		}	

		if (pnumarray_) {
			destruct_dealloc_array(pnumarray_, nin_elems_, arr_free_fp_);
			pnumarray_ = nullptr;
		}
		else if (pstrarray_) {
			destruct_dealloc_array(pstrarray_, nin_elems_, arr_free_fp_);
			pstrarray_ = nullptr;
		}
	}	

	CRITERION_ONE(const CRITERION_ONE &)			= delete;
	CRITERION_ONE & operator=(const CRITERION_ONE &)	= delete;

	CRITERION_ONE(CRITERION_ONE && other) noexcept
		: subsys_str_(other.subsys_str_), pfield1_(other.pfield1_), subsys_(other.subsys_), fieldtype_(other.fieldtype_), comp_(other.comp_), 
		valtype_(other.valtype_), is_valid_(other.is_valid_), is_timestamp_sec_(other.is_timestamp_sec_), math_oper_(other.math_oper_),
		hash_(other.hash_), pfield2_(other.pfield2_), field2_const_(other.field2_const_), numval_(std::move(other.numval_)),
		strval_(std::move(other.strval_)), boolval_(std::move(other.boolval_)), pexpr_val_(std::exchange(other.pexpr_val_, nullptr)),
		pregex_(std::exchange(other.pregex_, nullptr)), regex_free_fp_(other.regex_free_fp_),
		nin_elems_(std::exchange(other.nin_elems_, 0)), pnumarray_(std::exchange(other.pnumarray_, nullptr)),
		pstrarray_(std::exchange(other.pstrarray_, nullptr)), arr_free_fp_(other.arr_free_fp_)
	{
		other.numval_.reset();
		other.strval_.reset();
		other.boolval_.reset();
	}	

	CRITERION_ONE & operator= (CRITERION_ONE && other) noexcept
	{
		if (this != &other) {
			this->~CRITERION_ONE();
			new (this) CRITERION_ONE(std::move(other));
		}

		return *this;
	}	
	
	bool is_regex_compare() const noexcept
	{
		return ((comp_ == COMP_LIKE) || (comp_ == COMP_NOTLIKE));
	}

	JSON_TYPES_E get_value_type() const noexcept
	{
		return valtype_;
	}

	bool is_value_string() const noexcept
	{
		return valtype_ == JSON_STRING && !is_timestamp_sec_;
	}

	bool is_value_expression() const noexcept
	{
		return pexpr_val_ != nullptr;
	}	

	bool is_field_math_operator() const noexcept
	{
		return math_oper_ != 0;
	}	

	uint32_t get_value_elem_count() const noexcept
	{
		if (nin_elems_ == 0) return 1;
		return nin_elems_;
	}
	
	SUBSYS_CLASS_E get_subsys() const noexcept
	{
		return subsys_;
	}

	uint32_t get_field_crc() const noexcept
	{
		return pfield1_->jsoncrc;	// Will only return field1 (pfield1_ is non-null)
	}

	COMPARATORS_E get_comparator() const noexcept
	{
		return comp_;
	}

	uint64_t get_hash() const noexcept
	{
		return hash_;
	}	

	bool is_valid() const noexcept
	{
		return is_valid_;
	}	

	template <typename FCBNum, typename FCBString, typename FCBBool>
	bool match_criterian(FCBNum & get_num_field, FCBString & get_str_field, FCBBool & get_bool_field, time_t tcurr = 0) const 
	{
		if (!pfield1_ || !is_valid_) {
			return false;
		}

		if (fieldtype_ == JSON_NUMBER || is_timestamp_sec_) {

			NUMBER_CRITERION		n1, n2;
			NUMBER_TYPES_E			type;

			n1 = get_num_field(pfield1_, subsys_);

			if (false == n1.is_valid()) {
				return false;
			}	

			type = n1.get_type();

			if (force_double_) {
				int64_t		num = n1.get_int64();

				n1 = double(num);
				type = NUM_DOUBLE;
			}	

			if (math_oper_) {
				NUMBER_CRITERION	ni2;
				bool			bret;
				
				if (pfield2_) {
					ni2 = get_num_field(pfield2_, subsys_);
				}
				else {
					ni2 = NUMBER_CRITERION(field2_const_);
				}	

				if (false == ni2.is_valid()) {
					return false;
				}	

				bret = n1.apply_math_oper(math_oper_, ni2);

				if (bret == false) {
					// Divide by Zero
					return false;
				}	
			}	


			if (numval_) {
				/*
				 * If now() function used in expression and tcurr == 0, use the time of construction
				 */
				if (false == is_time_func_ || 0 == tcurr) {
					n2 	= *numval_;
				}
				else {
					n2 	= tcurr;
				}	
				type 	= n2.get_type();

				if (force_double_) {
					type = NUM_DOUBLE;
				}	
			}	
			else if (pexpr_val_) {
				n2 = get_num_field(pexpr_val_, subsys_);

				if (false == n2.is_valid()) {
					return false;
				}	
			}
			else if (!pnumarray_) {
				return false;
			}	

			switch (type) {
			
			case NUM_INT8 : 
				do {
					int8_t		input, crit;

					crit = n2.get_int8();
					input = n1.get_int8();

					return match_num_criterian(input, crit);
				} while (false);

			case NUM_INT16 : 
				do {
					int16_t		input, crit;

					crit = n2.get_int16();
					input = n1.get_int16();

					return match_num_criterian(input, crit);
				} while (false);


			case NUM_INT32 :
				do {
					int32_t		input, crit;

					crit = n2.get_int32();
					input = n1.get_int32();

					return match_num_criterian(input, crit);
				} while (false);


			case NUM_INT64 :
				do {
					int64_t		input, crit;

					crit = n2.get_int64();
					input = n1.get_int64();

					return match_num_criterian(input, crit);
				} while (false);


			case NUM_DOUBLE :
				do {
					double		input, crit;

					crit = n2.get_dbl();
					input = n1.get_dbl();

					return match_num_criterian(input, crit);
				} while (false);

			default	:		
				return false;
			}	
		}
		else if (fieldtype_ == JSON_STRING) {
			std::pair<const char *, uint32_t>	n1, n2;
			char					tbuf[1024], tbuf2[1024];

			n1 = get_str_field(pfield1_, tbuf, sizeof(tbuf), subsys_);

			if (nullptr == n1.first) {
				return false;
			}	

			if (strval_) {
				n2.first 	= strval_->get();
				n2.second	= strval_->size();
			}	
			else if (pexpr_val_) {
				n2 = get_str_field(pexpr_val_, tbuf2, sizeof(tbuf2), subsys_);

				if (nullptr == n2.first) {
					return false;
				}	
			}
			else if (!pstrarray_) {
				return false;
			}	

			return match_str_criterian(n1.first, n1.second, n2.first, n2.second);
		}
		else if (fieldtype_ == JSON_BOOL) {
			BOOL_CRITERION		n1, n2;

			n1 = get_bool_field(pfield1_, subsys_);

			if (false == n1.is_valid()) {
				return false;
			}	

			if (boolval_) {
				n2 = *boolval_;
			}	
			else if (pexpr_val_) {
				n2 = get_bool_field(pexpr_val_, subsys_);

				if (false == n2.is_valid()) {
					return false;
				}	
			}
			else {
				return false;
			}	

			return match_bool_criterian(n1.get(), n2.get());
		}	
		
		return false;
	}	

	bool set_db_filter(STR_WR_BUF & strbuf, const char *table_alias_prefix, const char *fallback) const
	{
		if (!pfield1_ || !is_valid_) {
			strbuf.append(fallback);
			return false;
		}

		if (pfield1_->dbcolname[0] == 0) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Cannot set DB filter for query expression as field \'%s\' not present in DB schema", pfield1_->jsonfield);
		}

		if (math_oper_ && pfield2_ && pfield2_->dbcolname[0] == 0) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Cannot set DB filter for query expression as field \'%s\' not present in DB schema", pfield2_->jsonfield);
		}	

		if (comp_ == COMP_BIT2 || comp_ == COMP_BIT3) {
			if (pfield1_->numtype == NUM_NAN) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Cannot set bit DB filter for query as field \'%s\' is not of integral type in DB schema", pfield1_->jsonfield);
			}

			int		n = (comp_ == COMP_BIT3) ? 7 : 3;

			if (math_oper_) {
				if (pfield2_) {
					strbuf.appendfmt("(((%s%s %c %s%s)::int & %d) = %d)", table_alias_prefix, pfield1_->dbcolname, math_oper_, table_alias_prefix, pfield2_->dbcolname, n, n);
				}
				else {
					strbuf.appendfmt("(((%s%s %c %.3g)::int & %d) = %d)", table_alias_prefix, pfield1_->dbcolname, math_oper_, field2_const_, n, n);
				}	
			}
			else {
				strbuf.appendfmt("((%s%s::int & %d) = %d)", table_alias_prefix, pfield1_->dbcolname, n, n);
			}	

			return true;

		}	
		else if ((comp_ == COMP_SUBSTR || comp_ == COMP_NOTSUBSTR) && strval_) {
			// (strpos(field, 'str') = / != 0)

			if (pfield1_->dbstrtype == DB_STR_NONE) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Cannot set substring DB filter for query as field \'%s\' is not of string type in DB schema", pfield1_->jsonfield);
			}

			strbuf.appendfmt("(strpos(%s%s, ", table_alias_prefix, pfield1_->dbcolname);
			strval_->set_db_filter(strbuf, pfield1_);
			strbuf.appendfmt(") %s 0)", comp_ == COMP_SUBSTR ? "!=" : "=");

			return true;
		}	

		if (!math_oper_) {
			strbuf.appendfmt("(%s%s", table_alias_prefix, pfield1_->dbcolname);
		}
		else {
			if (pfield2_) {
				if (math_oper_ == '/' || math_oper_ == '%') {
					strbuf.appendfmt("((%s%s %c nullif(%s%s, 0))", table_alias_prefix, pfield1_->dbcolname, math_oper_, table_alias_prefix, pfield2_->dbcolname);
				}
				else {
					strbuf.appendfmt("((%s%s %c %s%s)", table_alias_prefix, pfield1_->dbcolname, math_oper_, table_alias_prefix, pfield2_->dbcolname);
				}
			}
			else {
				if (!is_timestamp_sec_) {
					strbuf.appendfmt("((%s%s %c %.3g)", table_alias_prefix, pfield1_->dbcolname, math_oper_, field2_const_);
				}
				else {
					strbuf.appendfmt("((%s%s %c \'%ld sec\'::interval)", table_alias_prefix, pfield1_->dbcolname, math_oper_, (long)field2_const_);
				}	
			}	
		}	

		switch (comp_) {
		
		case COMP_EQ		:	strbuf << " = "; break;

		case COMP_NEQ		:	strbuf << " != "; break;

		case COMP_LT		:	strbuf << " < "; break;

		case COMP_LE		:	strbuf << " <= "; break;

		case COMP_GT		:	strbuf << " > "; break;

		case COMP_GE		:	strbuf << " >= "; break;

		case COMP_LIKE		:	strbuf << " ~ "; break;

		case COMP_NOTLIKE	:	strbuf << " !~ "; break;

		case COMP_IN		:	strbuf << " in "; break;

		case COMP_NOTIN		:	strbuf << " not in "; break;

		default			:	GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid comparator while creating DB filter");
		}

		// Keep the strval_ first for timestamptz case as both strval_ and numval_ will be valid there
		if (strval_) {
			strval_->set_db_filter(strbuf, pfield1_);
		}
		else if (numval_) {
			if (!is_time_func_) {
				numval_->set_db_filter(strbuf, pfield1_);
			}
			else {
				strbuf << " now() ";
			}	
		}	
		else if (boolval_) {
			boolval_->set_db_filter(strbuf, pfield1_);
		}	
		else if (pexpr_val_) {
			if (pexpr_val_->dbcolname[0] == 0) {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Cannot set DB filter for query expression as field expression \'%s\' not present in DB schema", pexpr_val_->jsonfield);
			}

			strbuf.appendfmt("%s%s", table_alias_prefix, pexpr_val_->dbcolname);
		}	
		else {
			if (pnumarray_) {
				strbuf.append('('); 

				for (uint32_t i = 0; i < nin_elems_; ++i) {
					
					pnumarray_[i].set_db_filter(strbuf, pfield1_);

					if (i + 1 < nin_elems_) {
						strbuf.append(',');
					}	
				}	

				strbuf.append(')');
			}
			else if (pstrarray_) {
				strbuf.append('('); 

				for (uint32_t i = 0; i < nin_elems_; ++i) {
					
					pstrarray_[i].set_db_filter(strbuf, pfield1_);

					if (i + 1 < nin_elems_) {
						strbuf.append(',');
					}	
				}	

				strbuf.append(')');
			}
			else {
				GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Cannot set DB filter for query expression as no valid value present");
			}	
		}	

		strbuf.append(')');

		return true;
	}	

	template <typename Num>
	bool match_num_criterian(Num input, Num crit) const noexcept
	{
		if (std::is_same_v<Num, double>) { 
			return match_dbl_criterian(input, crit); 
		}

		switch (comp_) {
		
		case COMP_EQ		:	return input == crit;

		case COMP_NEQ		:	return input != crit;

		case COMP_LT		:	return input < crit;

		case COMP_LE		:	return input <= crit;

		case COMP_GT		:	return input > crit;

		case COMP_GE		:	return input >= crit;

		case COMP_BIT2		:	return (((int)input & 3) == 3);

		case COMP_BIT3		:	return (((int)input & 7) == 7);

		case COMP_IN		:
		case COMP_NOTIN		:
				if (pnumarray_) {
					bool		bret = (comp_ == COMP_IN ? true : false);

					for (uint32_t i = 0; i < nin_elems_; ++i) {
						Num		icrit;

						icrit = pnumarray_[i].get<Num>();

						if (input == icrit) {
							return bret;
						}	
					}	
					
					return !bret;
				}
				return false;
			
		default			:	return false;	
		}
	}	

	bool match_dbl_criterian(double input, double crit) const noexcept
	{
		switch (comp_) {
		
		case COMP_EQ		:	return gy_is_dbl_equal(input, crit);

		case COMP_NEQ		:	return !gy_is_dbl_equal(input, crit);

		case COMP_LT		:	return input < crit && (crit - input > std::numeric_limits<double>::epsilon());

		case COMP_LE		:	return gy_is_dbl_equal(input, crit) || (input < crit);

		case COMP_GT		:	return input > crit && (input - crit > std::numeric_limits<double>::epsilon());

		case COMP_GE		:	return gy_is_dbl_equal(input, crit) || (input > crit);

		case COMP_BIT2		:	return (((int)input & 3) == 3);

		case COMP_BIT3		:	return (((int)input & 7) == 7);

		case COMP_IN		:
		case COMP_NOTIN		:
				if (pnumarray_) {
					bool		bret = (comp_ == COMP_IN ? true : false);

					for (uint32_t i = 0; i < nin_elems_; ++i) {
						double			icrit;

						icrit = pnumarray_[i].get<double>();

						if (gy_is_dbl_equal(input, icrit)) {
							return bret;
						}	
					}	
					
					return !bret;
				}
				return false;
			
		default			:	return false;	
		}
	}	

	/*
	 * The input may not be null terminated. So we use memmem
	 */
	bool match_str_criterian(const char * input, uint32_t szinput, const char * crit, uint32_t szcrit) const noexcept
	{
		switch (comp_) {
		
		case COMP_EQ		:	return (szinput == szcrit && input && crit && (0 == memcmp(input, crit, szcrit)));

		case COMP_NEQ		:	return (!(szinput == szcrit && input && crit && (0 == memcmp(input, crit, szcrit))));

		case COMP_SUBSTR	:	return (szcrit <= szinput && input && crit && (nullptr != memmem(input, szinput, crit, szcrit)));

		case COMP_NOTSUBSTR	:	return (!(szcrit <= szinput && input && crit && (nullptr != memmem(input, szinput, crit, szcrit))));

		case COMP_LIKE 		:
			if (!pregex_ || !pregex_->has_value() || !input) {
				return false;
			}
			return (true == RE2::PartialMatch(re2::StringPiece(input, szinput), *(*pregex_)));	

		case COMP_NOTLIKE 	:
			if (!pregex_ || !pregex_->has_value() || !input) {
				return false;
			}
			return (false == RE2::PartialMatch(re2::StringPiece(input, szinput), *(*pregex_)));	
		
		case COMP_IN		:
		case COMP_NOTIN		:
				if (pstrarray_ && input) {
					bool		bret = (comp_ == COMP_IN ? true : false);

					for (uint32_t i = 0; i < nin_elems_; ++i) {
						const char	*picrit;
						uint32_t	szicrit;

						picrit 		= pstrarray_[i].get();
						szicrit 	= pstrarray_[i].size();

						if (szinput == szicrit && picrit && (0 == memcmp(input, picrit, szicrit))) {
							return bret;
						}	
					}	
					
					return !bret;
				}
				return false;
			
		default			:	return false;	
		}
	}	

	bool match_bool_criterian(bool input, bool crit) const noexcept
	{
		switch (comp_) {
		
		case COMP_EQ		:	return input == crit;

		case COMP_NEQ		:	return input != crit;

		default			:	return false;
		
		}
	}	

	void init_regex()
	{
		if (!pregex_ || pregex_->has_value() || !bool(strval_)) {
			return;
		}	

		try {
			RE2::Options 		opt;

			opt.set_max_mem(1 << 20);
			opt.set_log_errors(false);

			pregex_->emplace(strval_->get(), opt);
		}	
		GY_CATCH_EXCEPTION(
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Failed to set regex for String Criterion for field \'%s\' due to %s", pfield1_ ? pfield1_->jsonfield : "", GY_GET_EXCEPT_STRING);
		);

		if (false == pregex_->value().ok()) {
			GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Invalid regex for String Criterion for field \'%s\' : %s", pfield1_ ? pfield1_->jsonfield : "", pregex_->value().error().c_str());
		}	
	}	

	std::pair<const NUMBER_CRITERION *, uint32_t> get_num_values() const noexcept
	{
		if (numval_) {
			return {std::addressof(*numval_), 1};
		}	

		if (pnumarray_) {
			return {pnumarray_, nin_elems_};
		}	

		return {nullptr, 0};
	}	

	std::pair<const STRING_CRITERION *, uint32_t> get_str_values() const noexcept
	{
		if (strval_) {
			return {std::addressof(*strval_), 1};
		}	

		if (pstrarray_) {
			return {pstrarray_, nin_elems_};
		}	

		return {nullptr, 0};
	}	

private :
	void parse_num_in_clause(const char *pin, const char *pend, const char *jsonfield, NUMBER_TYPES_E numtype, EXT_POOL_ALLOC *pextpool);

	void parse_str_in_clause(const char *pin, const char *pend, const char *jsonfield, EXT_POOL_ALLOC *pextpool);

};

enum GROUP_OPER_E : uint8_t
{
	OPER_OR		= 0,
	OPER_AND
};	

struct CRITERIA_ONE_GROUP final
{
	CRITERION_ONE			*pcritarr_		{nullptr};
	FREE_FPTR			arr_free_fp_		{nullptr};
	uint32_t			ncrit_			{0};
	uint32_t			maxcrit_		{0};
	GROUP_OPER_E			oper_			{OPER_OR};		
	uint8_t				level_			{0};

	CRITERIA_ONE_GROUP() noexcept	= default;

	CRITERIA_ONE_GROUP(uint32_t ncrit, GROUP_OPER_E oper, uint8_t level, EXT_POOL_ALLOC *pextpool = nullptr, bool allocregex = true)
		: maxcrit_(ncrit), oper_(oper), level_(level)
	{
		pcritarr_ = (CRITERION_ONE *)EXT_POOL_ALLOC::opt_safe_malloc(pextpool, ncrit * sizeof(CRITERION_ONE), arr_free_fp_);
	}	

	~CRITERIA_ONE_GROUP() noexcept
	{
		destroy();
	}

	void destroy() noexcept
	{
		if (pcritarr_) {
			destruct_dealloc_array(pcritarr_, ncrit_, arr_free_fp_);
			pcritarr_ = nullptr;
		}
	}	

	CRITERIA_ONE_GROUP(const CRITERIA_ONE_GROUP &)			= delete;
	CRITERIA_ONE_GROUP & operator= (const CRITERIA_ONE_GROUP &)	= delete;

	CRITERIA_ONE_GROUP(CRITERIA_ONE_GROUP && other) noexcept
		: pcritarr_(std::exchange(other.pcritarr_, nullptr)), arr_free_fp_(other.arr_free_fp_),
		ncrit_(std::exchange(other.ncrit_, 0)), maxcrit_(std::exchange(other.maxcrit_, 0)), oper_(other.oper_), level_(other.level_)
	{}

	CRITERIA_ONE_GROUP & operator= (CRITERIA_ONE_GROUP && other) noexcept
	{
		if (this != &other) {
			this->~CRITERIA_ONE_GROUP();	
			new (this) CRITERIA_ONE_GROUP(std::move(other));
		}

		return *this;
	}	

	CRITERION_ONE * add_criterion(const char *pcritstr, uint32_t szcrit, uint64_t hash, SUBSYS_CLASS_E subsys, const char *subsys_str, const JSON_DB_MAPPING **psubsys_map, uint32_t nmap_fields, EXT_POOL_ALLOC *pextpool, bool check_dollar_quote = false, bool allocregex = true) 
	{
		if (ncrit_ < maxcrit_) {
			if (check_dollar_quote) {
				if (nullptr != memmem(pcritstr, szcrit, "$a$", 3)) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Criteria cannot contain the text \'$a$\' or \'$b$\' as they are used as identifiers internally");
				}	

				if (nullptr != memmem(pcritstr, szcrit, "$b$", 3)) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, "Criteria cannot contain the text \'$a$\' or \'$b$\' as they are used as identifiers internally");
				}	
			}	

			auto			pcrit = pcritarr_ + ncrit_;

			new (pcrit) CRITERION_ONE(pcritstr, szcrit, hash, subsys, subsys_str, psubsys_map, nmap_fields, pextpool, allocregex);

			ncrit_++;
			return pcrit;
		}	

		return nullptr;
	}	

	template <typename FCBNum, typename FCBString, typename FCBBool, typename Map>
	CRIT_RET_E match_criteria_group(FCBNum & get_num_field, FCBString & get_str_field, FCBBool & get_bool_field, time_t tcurr, const SUBSYS_CLASS_E *pallowed_subsys_arr, size_t nsubsys, \
							Map & fmap, size_t max_mapsz) const 
	{
		uint64_t		fhash;
		uint32_t		neval = 0, nskip = 0;
		bool			iseval = false;

		for (uint32_t i = 0; i < ncrit_; ++i) {
			auto			pcrit = pcritarr_ + i;
			bool			bret = false, found;

			if (false == is_subsystem_allowed(pcrit->get_subsys(), pallowed_subsys_arr, nsubsys)) {
				nskip++;
				continue;
			}	
			
			neval++;

			fhash = pcrit->get_hash();

			if (fhash && (fmap.size() < max_mapsz)) {

				auto 			[mit, success] = fmap.try_emplace(fhash, false);

				if (success == false) {
					bret = mit->second;
				}
				else {
					bret = pcrit->match_criterian(get_num_field, get_str_field, get_bool_field, tcurr);

					mit->second = bret;
				}	
			}	
			else {
				found = false;

				if (fhash) {
					auto		it = fmap.find(fhash);

					if (it != fmap.end()) {
						bret 	= it->second;
						found 	= true;
					}
				}	

				if (found == false) {
					bret = pcrit->match_criterian(get_num_field, get_str_field, get_bool_field, tcurr);
				}
			}

			if (bret == true) {
				if (oper_ == OPER_OR) {
					return CRIT_PASS;
				}	
				iseval = true;
			}	
			else if (oper_ == OPER_AND) {
				return CRIT_FAIL;
			}	
		}	
	
		if (iseval && oper_ == OPER_AND) {
			return CRIT_PASS;
		}

		if (neval == 0 || nskip) {
			return CRIT_SKIP;
		}	

		return CRIT_FAIL;
	}	
	
	/*
	 * Iterate over each criterion within this group. The FCB should return CB_BREAK_LOOP to terminate the walk.
	 */
	template <typename FCB>
	size_t walk_criterion(FCB & fcb)
	{
		size_t			nwalk = 0;

		for (uint32_t i = 0; i < ncrit_; ++i) {
			auto			pcrit = pcritarr_ + i;
			CB_RET_E		cret;

			cret = fcb(*pcrit);

			nwalk++;

			if (cret == CB_BREAK_LOOP) {
				break;
			}	
		}	
	
		return nwalk;
	}	

	bool set_db_filter(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, const char *table_alias_prefix, const char *fallback, bool add_multihost_subsys = false, const char * host_table_alias = "thost.") const
	{
		bool			iseval = false;
		const char		*cfallback = (oper_ == OPER_OR ? "(false)" : "(true)");
		uint32_t		nsub = 1;
		SUBSYS_CLASS_E		subarr[2] {subsys, SUBSYS_HOST};

		if (add_multihost_subsys) {
			if (subsys != SUBSYS_HOST) {
				nsub = 2;
			}
			else {
				add_multihost_subsys = false;
			}	
		}	

		for (uint32_t i = 0; i < ncrit_; ++i) {
			auto			pcrit = pcritarr_ + i;
			auto			csub = pcrit->get_subsys();
			bool			bret = false, found;

			if (false == is_subsystem_allowed(csub, subarr, nsub)) {
				if ((iseval == true) && (i + 1 == ncrit_)) {
					strbuf.append(cfallback);
				}	
				continue;
			}	
			
			if (iseval == false) {
				iseval = true;
				strbuf.append('(');
			}	

			if (add_multihost_subsys && csub == SUBSYS_HOST) {
				pcrit->set_db_filter(strbuf, host_table_alias, cfallback);
			}
			else {
				pcrit->set_db_filter(strbuf, table_alias_prefix, cfallback);
			}	

			if (i + 1 < ncrit_) {
				if (oper_ == OPER_OR) {
					strbuf.appendconst(" or ");
				}	
				else {
					strbuf.appendconst(" and ");
				}	
			}
		}	
	
		if (iseval) {
			strbuf.append(')');
			return true;
		}

		strbuf.append(fallback);
		return false;
	}	

	bool has_subsystem(SUBSYS_CLASS_E subsys, bool match_all_criteria = false) const noexcept
	{
		bool			bret = false;

		for (uint32_t i = 0; i < ncrit_; ++i) {
			auto			pcrit = pcritarr_ + i;

			if (pcrit->get_subsys() == subsys) {

				if (match_all_criteria == false) {
					return true;
				}
				
				if (bret == false && i > 0) {
					return false;
				}

				bret = true;
			}	
			else if (bret && match_all_criteria) {
				return false;
			}	
		}	
		
		return bret;
	}	

	static bool is_subsystem_allowed(SUBSYS_CLASS_E subsys, const SUBSYS_CLASS_E *pallowed_subsys_arr, size_t nsubsys) noexcept
	{
		if (pallowed_subsys_arr) {
			for (size_t s = 0; s < nsubsys; ++s) {
				if (subsys == pallowed_subsys_arr[s]) {
					return true;
				}	
			}	
			
			return false;
		}	

		return true;
	};	
};	

class GY_BOOLPARSE;

class CRITERIA_SET final
{
public :	
	CRITERIA_ONE_GROUP		l1_grp_;

	CRITERIA_ONE_GROUP		*pl2_grp_		{nullptr};
	FREE_FPTR			arr_free_fp_		{nullptr};
	uint32_t			nl2_group_		{0};

	SUBSYS_CLASS_E			psubsys_arr_[2]		{};
	uint32_t			nsubsys_		{0};

	uint32_t			total_crit_		{0};
	GROUP_OPER_E 			l1_oper_		{OPER_OR};
	
	CRITERIA_SET() noexcept		= default;

	CRITERIA_SET(const char *filter, size_t lenfil, SUBSYS_CLASS_E subsys, EXT_POOL_ALLOC *pextpool = nullptr, bool is_multihost = true, bool allocregex = true);

	/*
	 * Constructor to be used in case custom columns are present which are different from subsys default columns
	 */
	CRITERIA_SET(const char *filter, size_t lenfil, SUBSYS_CLASS_E subsys, const char *subsys_str, const JSON_DB_MAPPING **psubsys_map, uint32_t nmap_fields, \
					EXT_POOL_ALLOC *pextpool = nullptr, bool is_multihost = true, bool allocregex = true);

	~CRITERIA_SET() noexcept
	{
		destroy();
	}

	void destroy() noexcept
	{
		if (pl2_grp_) {
			destruct_dealloc_array(pl2_grp_, nl2_group_, arr_free_fp_);
			pl2_grp_ = nullptr;
		}

		total_crit_ = 0;
	}	

	CRITERIA_SET(const CRITERIA_SET &)			= delete;
	CRITERIA_SET & operator= (const CRITERIA_SET &)		= delete;

	CRITERIA_SET(CRITERIA_SET && other) noexcept
		: l1_grp_(std::move(other.l1_grp_)), pl2_grp_(std::exchange(other.pl2_grp_, nullptr)), arr_free_fp_(other.arr_free_fp_),
		nl2_group_(std::exchange(other.nl2_group_, 0)), nsubsys_(other.nsubsys_), total_crit_(std::exchange(other.total_crit_, 0)), l1_oper_(other.l1_oper_)
	{
		psubsys_arr_[0]		= other.psubsys_arr_[0];
		psubsys_arr_[1]		= other.psubsys_arr_[1];
	}

	CRITERIA_SET & operator= (CRITERIA_SET && other) noexcept
	{
		if (this != &other) {
			this->~CRITERIA_SET();	
			new (this) CRITERIA_SET(std::move(other));
		}

		return *this;
	}	

	/*
	 * If tcurr == 0, the now() function if used in a criterion will use the time of construction of the object rather than current time.
	 * 
	 * If pallowed_subsys_arr == nullptr no subsys filter will be applied and all criteria will be evaluated.
	 * Use pallowed_subsys_arr only in cases where the evaluation is to be done in phases like alert evaluations spanning multiple subsystems.
	 *
	 * Returns CRIT_PASS if the criteria set matched, CRIT_FAIL if the set match failed. 
	 * CRIT_SKIP will be returned if no criteria or criteria match skipped due to pallowed_subsys_arr
	 */	
	template <typename FCBNum, typename FCBString, typename FCBBool>
	CRIT_RET_E match_criteria(FCBNum & get_num_field, FCBString & get_str_field, FCBBool & get_bool_field, time_t tcurr = 0, const SUBSYS_CLASS_E *pallowed_subsys_arr = nullptr, size_t nsubsys = 0) const 
	{
		if (total_crit_ == 0) {
			return CRIT_SKIP;
		}

		if (pallowed_subsys_arr) {
			for (size_t n = 0; n < nsubsys; ++n) {
				for (size_t s = 0; s < nsubsys_; ++s) {
					if (psubsys_arr_[s] == pallowed_subsys_arr[n]) {
						goto start1;
					}	
				}	
			}	

			return CRIT_SKIP;
		}	

start1 :
		constexpr size_t		max_cmap_entries	= 64;

		using Stackmap 			= INLINE_STACK_HASH_MAP<uint64_t, bool, 4 * 1024, GY_JHASHER<uint64_t>>;

		Stackmap			fmap;
		uint32_t			npass = 0, nfail = 0, nskip = 0;
		CRIT_RET_E			cret;

		fmap.reserve(total_crit_ < max_cmap_entries ? total_crit_ : max_cmap_entries);

		if (l1_grp_.ncrit_) {
			cret = l1_grp_.match_criteria_group(get_num_field, get_str_field, get_bool_field, tcurr, pallowed_subsys_arr, nsubsys, fmap, max_cmap_entries);

			if (cret != CRIT_FAIL) {
				if (cret == CRIT_PASS) {
					if (l1_oper_ == OPER_OR) {
						return CRIT_PASS;
					}	

					npass++;
				}
				else {
					nskip++;
				}	
			}	
			else {
				if (l1_oper_ == OPER_AND) {
					return CRIT_FAIL;
				}

				nfail++;
			}	
		}

		for (uint32_t i = 0; i < nl2_group_; ++i) {
			auto			pgrp = pl2_grp_ + i;

			cret = pgrp->match_criteria_group(get_num_field, get_str_field, get_bool_field, tcurr, pallowed_subsys_arr, nsubsys, fmap, max_cmap_entries);

			if (cret != CRIT_FAIL) {
				if (cret == CRIT_PASS) {
					if (l1_oper_ == OPER_OR) {
						return CRIT_PASS;
					}	

					npass++;
				}
				else {
					nskip++;
				}	
			}	
			else {
				if (l1_oper_ == OPER_AND) {
					return CRIT_FAIL;
				}

				nfail++;
			}	
		}	
	
		if (npass && nskip == 0) {
			return CRIT_PASS;
		}

		if (nskip && !nfail) {
			return CRIT_SKIP;
		}

		return CRIT_FAIL;
	}	
	
	/*
	 * Iterate over all the criteria. The FCB should return CB_BREAK_LOOP to terminate the walk.
	 */
	template <typename FCB>
	size_t walk_all_criteria(FCB & fcb)
	{
		size_t			ncrit = 0;

		if (total_crit_ == 0) {
			return 0;
		}

		for (uint32_t i = 0; i < l1_grp_.ncrit_; ++i) {
			auto			pcrit = l1_grp_.pcritarr_ + i;
			CB_RET_E		cret;
			
			cret = fcb(*pcrit, l1_grp_);

			ncrit++;

			if (cret == CB_BREAK_LOOP) {
				return ncrit;
			}	

		}

		for (uint32_t i = 0; i < nl2_group_; ++i) {
			auto			pgrp = pl2_grp_ + i;

			for (uint32_t i = 0; i < pgrp->ncrit_; ++i) {
				auto			pcrit = pgrp->pcritarr_ + i;
				CB_RET_E		cret;
				
				cret = fcb(*pcrit, *pgrp);

				ncrit++;

				if (cret == CB_BREAK_LOOP) {
					return ncrit;
				}	
			}
		}

		return ncrit;
	}	

	void init_criteria_regex() 
	{
		if (total_crit_ == 0) {
			return;
		}

		for (uint32_t i = 0; i < l1_grp_.ncrit_; ++i) {
			auto		pcrit = l1_grp_.pcritarr_ + i;
				
			pcrit->init_regex();
		}

		for (uint32_t i = 0; i < nl2_group_; ++i) {
			auto			pgrp = pl2_grp_ + i;

			for (uint32_t i = 0; i < pgrp->ncrit_; ++i) {
				auto		pcrit = pgrp->pcritarr_ + i;
				
				pcrit->init_regex();
			}
		}	
	}	

	/*
	 * Get the DB filters for a specific subsystem. If no criteria match this subsystem, append the fallback string to strbuf
	 * If add_multihost_subsys is true, then SUBSYS_HOST criteria will be appended to the db filter string
	 */
	char * get_db_filter_criteria(STR_WR_BUF & strbuf, SUBSYS_CLASS_E subsys, const char *table_alias_prefix = "", const char * fallback = "(true)", \
						bool add_multihost_subsys = false, const char * host_table_alias = "thost.") const
	{
		size_t			s, nc;
		const char		*cfallback = (l1_oper_ == OPER_OR ? "(false)" : "(true)");

		if (*table_alias_prefix) {
			assert(table_alias_prefix[strlen(table_alias_prefix) - 1] == '.');
		}	

		if (total_crit_ == 0) {
			strbuf.append(fallback);
			return strbuf.buffer();
		}

		for (s = 0; s < nsubsys_; ++s) {
			if (psubsys_arr_[s] == subsys) {
				break;
			}	
		}	
		
		if (s == nsubsys_) {
			strbuf.append(fallback);
			return strbuf.buffer();
		}	
		
		strbuf.appendconst(" ( ");
		
		if (l1_grp_.ncrit_) {
			l1_grp_.set_db_filter(strbuf, subsys, table_alias_prefix, cfallback, add_multihost_subsys, host_table_alias);

			if (nl2_group_ > 0) {
				if (l1_oper_ == OPER_OR) {
					strbuf.appendconst(" or ");
				}	
				else {
					strbuf.appendconst(" and ");
				}	
			}	
		}	
		
		for (uint32_t i = 0; i < nl2_group_; ++i) {
			auto			pgrp = pl2_grp_ + i;

			pgrp->set_db_filter(strbuf, subsys, table_alias_prefix, cfallback, add_multihost_subsys, host_table_alias);

			if (i + 1 < nl2_group_) {
				if (l1_oper_ == OPER_OR) {
					strbuf.appendconst(" or ");
				}	
				else {
					strbuf.appendconst(" and ");
				}	
			}	
		}	

		strbuf.appendconst(" ) ");

		if (strbuf.is_overflow()) {
			GY_THROW_EXPR_CODE(ERR_SERV_ERROR, "[Internal Error]: DB query buffer overflow encountered while creating DB filter from criteria");
		}

		return strbuf.buffer();
	}	

	uint32_t get_total_ncriteria() const noexcept
	{
		return total_crit_;
	}	

	bool has_filter_criteria() const noexcept
	{
		return !!total_crit_;
	}	

	bool is_only_l1() const noexcept
	{
		return (l1_grp_.ncrit_ && nl2_group_ == 0); 
	}

	bool is_l1_oper_or() const noexcept
	{
		return l1_oper_ == OPER_OR;
	}	

	bool has_subsystem(SUBSYS_CLASS_E subsys, bool match_all = false) const noexcept
	{
		bool			bret = false;

		for (uint32_t i = 0; i < nsubsys_; ++i) {
			if (psubsys_arr_[i] == subsys) {
				if (match_all == false) {
					return true;
				}
				
				if (bret == false && i > 0) {
					return false;
				}

				bret = true;
			}	
			else if (bret && match_all) {
				return false;
			}	
		}	
		
		return bret;
	}	

	/*
	 * Currently we do not support criteria groups where 1 group has a Host filter and other has none.
	 * This is due to the fact that in multihost cases, the host filter is applied first to narrow down the partha's
	 * to be targetted.
	 */
	void validate_multihost_criteria() const 
	{
		bool			bret;

		if ((total_crit_ == 0) || (false == has_subsystem(SUBSYS_HOST))) {
			return;
		}

		if (l1_grp_.ncrit_) {
			bret = l1_grp_.has_subsystem(SUBSYS_HOST, l1_oper_ == OPER_OR /* match_all_criteria */);

			if (bret == false) {
				if (l1_oper_ == OPER_OR) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, 
						"Criteria with OR clause where one of the clauses is a Host filter while others are not is currently not supported for a Multi Host Query");
				}	
			}	
		}

		for (uint32_t i = 0; i < nl2_group_; ++i) {
			auto			pgrp = pl2_grp_ + i;

			bret = pgrp->has_subsystem(SUBSYS_HOST, false /* match_all_criteria */);

			if (bret == false) {
				if (l1_oper_ == OPER_OR) {
					GY_THROW_EXPR_CODE(ERR_INVALID_REQUEST, 
						"Multiple Criteria with AND clauses where one of the clause groups has a Host filter while others do not is currently not supported for a Multi Host Query");
				}	
			}	
		}	
	}	

private :
	
	void populate_groups(GY_BOOLPARSE & boolparse, const char *subsys_str, const JSON_DB_MAPPING **psubsys_map, uint32_t nmap_fields, \
				EXT_POOL_ALLOC *pextpool, const SUBSYS_CLASS_E *pallowed_subsys_arr, size_t nsubsys, bool is_multihost, bool allocregex);
};	


} // namespace gyeeta

