
#include		"gy_common_inc.h"
#include		"gy_stack_pool.h"

using namespace gyeeta;


enum TNUMBER_TYPES_E : uint8_t
{
	NUM_INT8		= 0,
	NUM_INT16,
	NUM_INT32,
	NUM_INT64,
	NUM_DOUBLE,

	NUM_NAN,
};


struct TNUMBER_CRITERION
{
	union {
		int8_t		int8;
		int16_t		int16;
		int32_t		int32;
		int64_t		int64		{0L};
		double		dbl;
	};

	TNUMBER_TYPES_E		type_		{NUM_NAN};
	bool			isvalid_	{false};		

	TNUMBER_CRITERION() noexcept		= default;

	TNUMBER_CRITERION(const char *str, TNUMBER_TYPES_E type) noexcept
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

	TNUMBER_CRITERION(int8_t val) noexcept : int8(val), type_(NUM_INT8), isvalid_(true) {}

	TNUMBER_CRITERION(int16_t val) noexcept : int16(val), type_(NUM_INT16), isvalid_(true) {}

	TNUMBER_CRITERION(int32_t val) noexcept : int32(val), type_(NUM_INT32), isvalid_(true) {}

	TNUMBER_CRITERION(int64_t val) noexcept : int64(val), type_(NUM_INT64), isvalid_(true) {}

	TNUMBER_CRITERION(double val) noexcept : dbl(val), type_(NUM_DOUBLE), isvalid_(true) {}

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

	TNUMBER_TYPES_E get_type() const noexcept
	{
		return type_;
	}

	bool is_valid() const noexcept
	{
		return isvalid_;
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

struct TSTRING_CRITERION final
{
	char			*str_		{nullptr};
	FREE_FPTR		free_fp_	{nullptr};
	uint32_t		len_		{0};
	uint32_t		maxlen_		{0};

	TSTRING_CRITERION() noexcept		= default;

	TSTRING_CRITERION(const char *str, uint32_t len, STACK_POOL_ALLOC_64K *pstackpool = nullptr)
	{
		if (pstackpool) {
			str_		= (char *)pstackpool->safe_malloc(len + 1, free_fp_, maxlen_);
		}
		else {
			str_		= (char *)malloc_or_throw(len + 1);
			free_fp_	= ::free;
			maxlen_		= len + 1; 	
		}	

		std::memcpy(str_, str, len);
		str_[len]	= 0;
		len_		= len;
	}	

	~TSTRING_CRITERION() noexcept
	{
		if (str_) {
			if (free_fp_) {
				(*free_fp_)(str_);
			}

			str_ = nullptr;
		}	
	}

	TSTRING_CRITERION(const TSTRING_CRITERION &)			= delete;
	TSTRING_CRITERION & operator= (const TSTRING_CRITERION &)	= delete;

	TSTRING_CRITERION(TSTRING_CRITERION && other) noexcept
		: str_(std::exchange(other.str_, nullptr)), free_fp_(other.free_fp_), len_(std::exchange(other.len_, 0)), maxlen_(other.maxlen_)
	{}

	TSTRING_CRITERION & operator= (TSTRING_CRITERION && other) noexcept
	{
		if (this != &other) {
			this->~TSTRING_CRITERION();
			new (this) TSTRING_CRITERION(std::move(other));
		}

		return *this;
	}	

	char * get() const noexcept
	{
		return str_;
	}	

	bool is_valid() const noexcept
	{
		return str_ != nullptr;
	}	

	static bool valid_start_string(const char *str) noexcept
	{
		return *str == '\'';
	}	
};



STACK_POOL_ALLOC_64K		*pstackpool = nullptr;
TNUMBER_CRITERION		*pnumarray_ = nullptr;
TSTRING_CRITERION		*pstrarray_ = nullptr;
FREE_FPTR			arr_free_fp_ {nullptr};

TNUMBER_TYPES_E			numtype = NUM_INT32;

size_t parse_num_in(const char *pin, const char *pend)
{
	const char			*pstartnum = pin, *ptmp = pin, *pendnum;
	size_t				nelems = 0;
	std::pair<const char *, size_t>	tarray[65];

	do {
		while (ptmp < pend && (*ptmp == ' ' || *ptmp == '\t' || *ptmp == ',')) ptmp++;
		pstartnum = ptmp++;

		if (false == TNUMBER_CRITERION::valid_start_string(pstartnum)) {
			if (pstartnum >= pend) {
				break;
			}	
			GY_THROW_EXCEPTION("Invalid Criterion format : Value \'%s\' not a valid Number", pstartnum);
		}	

		while (ptmp < pend && (*ptmp != ' ' && *ptmp != '\t' && *ptmp != ',')) ptmp++;
		pendnum = ptmp;

		tarray[nelems++] = {pstartnum, pendnum - pstartnum};

	} while (ptmp < pend && nelems < GY_ARRAY_SIZE(tarray));

	if (nelems == GY_ARRAY_SIZE(tarray)) {
		GY_THROW_EXCEPTION("Invalid Criterion format : Max elements for \'in\' expression reached %lu", GY_ARRAY_SIZE(tarray));
	}	
	
	if (pstackpool) {
		uint32_t		act_size;

		pnumarray_ = (TNUMBER_CRITERION *)pstackpool->safe_malloc(nelems * sizeof(TNUMBER_CRITERION), arr_free_fp_, act_size);
	}
	else {
		pnumarray_ = (TNUMBER_CRITERION *)malloc_or_throw(nelems * sizeof(TNUMBER_CRITERION));
		arr_free_fp_ = ::free;
	}	
	
	for (size_t i = 0; i < nelems; ++i) {
		new (pnumarray_ + i) TNUMBER_CRITERION(tarray[i].first, numtype);

		if (false == pnumarray_[i].is_valid()) {
			GY_THROW_EXCEPTION("Invalid Criterion format : Value \'%s\' not a valid Number", 
				CHAR_BUF<128>(tarray[i].first, tarray[i].second).get());
		}	
	}	

	return nelems;
}

size_t parse_str_in(const char *pin, const char *pend)
{
	const char			*pstartstr = pin, *ptmp = pin, *pendstr;
	size_t				nelems = 0;
	std::pair<const char *, size_t>	tarray[65];

	do {
		while (ptmp < pend && (*ptmp == ' ' || *ptmp == '\t' || *ptmp == ',')) ptmp++;
		pstartstr = ptmp++;

		if (false == TSTRING_CRITERION::valid_start_string(pstartstr)) {
			if (pstartstr >= pend) {
				break;
			}	
			GY_THROW_EXCEPTION("Invalid Criterion format : Value \'%s\' not a valid String type as quote missing", pstartstr);
		}	

		while (ptmp < pend && (*ptmp != '\'')) ptmp++;

		if (ptmp < pend) {
			ptmp++;
		}
		else {
			GY_THROW_EXCEPTION("Invalid Criterion format : Value \'%s\' string delimiter \' missing", pstartstr);
		}	

		pendstr = ptmp;

		if (pstartstr + 2 == pendstr) {
			continue;
		}

		tarray[nelems++] = {pstartstr, pendstr - pstartstr};

	} while (ptmp < pend && nelems < GY_ARRAY_SIZE(tarray));

	if (nelems == GY_ARRAY_SIZE(tarray)) {
		GY_THROW_EXCEPTION("Invalid Criterion format : Max elements for \'in\' expression reached %lu", GY_ARRAY_SIZE(tarray));
	}	
	else if (nelems == 0) {
		GY_THROW_EXCEPTION("Invalid Criterion format : Value \'%s\' no valid strings within the \'in\' clause", 
			CHAR_BUF<128>(pin, pend - pin).get());
	}
	
	if (pstackpool) {
		uint32_t		act_size;

		pstrarray_ = (TSTRING_CRITERION *)pstackpool->safe_malloc(nelems * sizeof(TSTRING_CRITERION), arr_free_fp_, act_size);
	}
	else {
		pstrarray_ = (TSTRING_CRITERION *)malloc_or_throw(nelems * sizeof(TSTRING_CRITERION));
		arr_free_fp_ = ::free;
	}	
	
	for (size_t i = 0; i < nelems; ++i) {
		new (pstrarray_ + i) TSTRING_CRITERION(tarray[i].first, tarray[i].second, pstackpool);

		if (false == pstrarray_[i].is_valid()) {
			GY_THROW_EXCEPTION("Invalid Criterion format : Value \'%s\' not a valid String type", 
				CHAR_BUF<128>(tarray[i].first, tarray[i].second).get());
		}	
	}	

	return nelems;
}


int main()
{
	STACK_POOL_ALLOC_64K	stackpool;
	size_t			nin_elems_ = 0;

	pstackpool = &stackpool;
	
	const char 		num_in_str[] = "-123, 0, 12,   134,13,+1,-2		,0";
	const char 		num_in_str2[] = "3, ,0";
	const char 		num_in_str3[] = "-1, as12, 0";
	const char 		num_in_str4[] = "12, 0, 1334a";
	const char 		num_in_str5[] = "1";

	const char 		*arrnum[] = {num_in_str, num_in_str2, num_in_str3, num_in_str4, num_in_str5};

	const char 		str_in_str[] = "\' This is atest1, with1\',  \'Another st, 1. 1\',\'third str1\'  ";
	const char 		str_in_str2[] = "\' This is atest1, with1\' ";
	const char 		str_in_str3[] = "\' a \', another, 1 ";
	const char 		str_in_str4[] = "\' a \', \'another, 1 \', \'1\'";
	const char 		str_in_str5[] = "\'";
	const char 		str_in_str6[] = "\'\'";

	const char 		*arrstr[] = {str_in_str, str_in_str2, str_in_str3, str_in_str4, str_in_str5, str_in_str6};


	for (size_t i = 0; i < GY_ARRAY_SIZE(arrnum); ++i) {
		
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Number In Comparator for \'%s\'...\n", arrnum[i]);
		
		try {
			nin_elems_ = parse_num_in(arrnum[i], arrnum[i] + strlen(arrnum[i]));

			INFOPRINTCOLOR(GY_COLOR_CYAN, "#elems in comp array = %lu : [", nin_elems_);

			for (size_t n = 0; n < nin_elems_; ++n) {
				int64_t			int64;
				int32_t			int32;
				int16_t			int16;
				int8_t			int8;
				double			dbl;

				switch (pnumarray_[n].get_type()) {
				
				case NUM_INT8 : 	
					int8 = pnumarray_[n].get_int8(); 

					IRPRINT("%hhd,", int8);
					break;

				case NUM_INT16 :
					int16 = pnumarray_[n].get_int16(); 

					IRPRINT("%hd,", int16);
					break;

				case NUM_INT32 :
					int32 = pnumarray_[n].get_int32(); 

					IRPRINT("%d,", int32);
					break;

				case NUM_INT64 :
					int64 = pnumarray_[n].get_int64(); 

					IRPRINT("%ld,", int64);
					break;

				case NUM_DOUBLE :
					dbl = pnumarray_[n].get_dbl(); 

					IRPRINT("%.3lf,", dbl);
					break;

				default	:
					break;
				}	
			}	

			IRPRINT("]\n\n");
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to parse : %s\n\n", GY_GET_EXCEPT_STRING);
		);

		if (pnumarray_) {
			destruct_dealloc_array(pnumarray_, nin_elems_, arr_free_fp_);
			pnumarray_ = nullptr;

			stackpool.reset_ext();
		}
	}

	nin_elems_ = 0;

	for (size_t i = 0; i < GY_ARRAY_SIZE(arrstr); ++i) {
		
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Testing String In Comparator for %s...\n", arrstr[i]);
		
		try {
			nin_elems_ = parse_str_in(arrstr[i], arrstr[i] + strlen(arrstr[i]));

			INFOPRINTCOLOR(GY_COLOR_GREEN, "#elems in comp array = %lu : [", nin_elems_);

			for (size_t n = 0; n < nin_elems_; ++n) {
				IRPRINT("%s,", pstrarray_[n].get());
			}	

			IRPRINT("]\n\n");
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to parse : %s\n\n", GY_GET_EXCEPT_STRING);
		);

		if (pstrarray_) {
			destruct_dealloc_array(pstrarray_, nin_elems_, arr_free_fp_);
			pstrarray_ = nullptr;

			stackpool.reset_ext();
		}
	}

}	

