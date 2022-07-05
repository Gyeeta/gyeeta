
#include		"gy_common_inc.h"

using namespace gyeeta;

template <size_t szbuf_>
class MCHAR_BUF
{
public :	
	char			buf_[szbuf_];

	MCHAR_BUF() noexcept
	{
		*buf_		= '\0';
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Within MCHAR_BUF default constructor...\n\n");
	}

	MCHAR_BUF(const char * pmsg) noexcept
	{
		GY_STRNCPY(buf_, pmsg, szbuf_);
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Within MCHAR_BUF constructor with pmsg %s ...\n\n", pmsg);
	}

	~MCHAR_BUF() noexcept
	{
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Within MCHAR_BUF destructor : buf_ is \'%s\'\n\n", buf_);
		GY_STRNCPY(buf_, "BUFFER DESTROYED", szbuf_);
	}

	MCHAR_BUF(const MCHAR_BUF & other) noexcept
	{
		INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Within MCHAR_BUF copy constructor...\n\n");
		std::memcpy(buf_, other.buf_, sizeof(buf_));
	}

	MCHAR_BUF(MCHAR_BUF && other) noexcept
	{
		INFOPRINTCOLOR(GY_COLOR_BLUE, "Within MCHAR_BUF move constructor...\n\n");
		std::memcpy(buf_, other.buf_, sizeof(buf_));
		GY_STRNCPY(other.buf_, "BUFFER MOVED", szbuf_);
	}

	MCHAR_BUF & get_ref() noexcept
	{
		return *this;
	}

	char * get() noexcept
	{
		return buf_;
	}	

	size_t maxsz() const noexcept
	{
		return szbuf_;
	}	
};

[[gnu::noinline]] char * print_msg(STR_WR_BUF strbuf = STRING_BUFFER<512>()) noexcept
{
	strbuf.appendfmt("Printing Current time : %s", gy_localtime_iso8601(get_timeval(), CHAR_BUF<128>().get(), 128));
	return strbuf.buffer();
}

[[gnu::noinline]] char * print_msg3(MCHAR_BUF<512> && mchar) noexcept
{
	STR_WR_BUF		strbuf(mchar.get(), 512);
	strbuf.appendfmt("From print_msg3 : Printing Current time : %s", gy_localtime_iso8601(get_timeval(), CHAR_BUF<128>().get(), 128));

	return strbuf.buffer();
}	

[[gnu::noinline]] STRING_BUFFER<512> print_msg2() noexcept
{
	STRING_BUFFER<512>		strbuf;
	strbuf.appendfmt("From print_msg2 : Printing Current time : %s", gy_localtime_iso8601(get_timeval(), CHAR_BUF<128>().get(), 128));

	return strbuf;
}	


[[gnu::noinline]] MCHAR_BUF<512> get_buf() noexcept
{
	MCHAR_BUF<512>		buf;

	return buf;
}	

[[gnu::noinline]] std::array<char, 512> get_buf2() noexcept
{
	std::array<char, 512>		buf;

	return buf;
}

[[gnu::noinline]] const char * print_except(MCHAR_BUF<512> && mchar) 
{
	snprintf(mchar.get(), mchar.maxsz(), "Within print_except() now calling throw exception...");

	if (0 < time(nullptr)) {
		throw std::runtime_error("Throwing from print_except()");
	}
	
	return mchar.get();
}	

[[gnu::noinline]] const char * print_except(MCHAR_BUF<512> & mchar) 
{
	snprintf(mchar.get(), mchar.maxsz(), "Within lref print_except() now calling throw exception...");

	if (0 < time(nullptr)) {
		throw std::runtime_error("Throwing from lref print_except()");
	}
	
	return mchar.get();
}	

using SHRCHR = MCHAR_BUF<512>;

struct SHRWRAP
{
	std::shared_ptr<SHRCHR>		shr_;

	SHRWRAP()
	{
		INFOPRINTCOLOR(GY_COLOR_BLUE, "Within SHRWRAP constructor...\n\n");
		shr_ = std::make_shared<SHRCHR>("Shared Ptr");
	}

	~SHRWRAP() noexcept
	{
		INFOPRINTCOLOR(GY_COLOR_BLUE, "Within SHRWRAP destructor...\n\n");
	}	

	SHRWRAP(const SHRWRAP & other) noexcept
		: shr_(other.shr_)
	{
		INFOPRINTCOLOR(GY_COLOR_BLUE, "Within SHRWRAP copy constructor...\n\n");
	}	

	SHRWRAP(SHRWRAP && other) noexcept
		: shr_(std::move(other.shr_))
	{
		INFOPRINTCOLOR(GY_COLOR_BLUE, "Within SHRWRAP move constructor...\n\n");
	}	

	SHRWRAP & operator=(const SHRWRAP & other) noexcept
	{
		INFOPRINTCOLOR(GY_COLOR_BLUE, "Within SHRWRAP copy constructor...\n\n");
		
		shr_ = other.shr_;

		return *this;
	}	

	SHRWRAP & operator=(SHRWRAP && other) noexcept
	{
		INFOPRINTCOLOR(GY_COLOR_BLUE, "Within SHRWRAP move constructor...\n\n");
		
		shr_ = std::move(other.shr_);

		return *this;
	}	
};	

std::weak_ptr<SHRWRAP>		gweakshr;


[[gnu::noinline]] std::shared_ptr<SHRWRAP> get_shared() noexcept
{
	return gweakshr.lock();
}	

int main()
{
	using mchar_htbl = std::unordered_map<uint64_t, MCHAR_BUF<512>>;

	mchar_htbl		mtbl;

	INFOPRINTCOLOR(GY_COLOR_GREEN, "%s\n", print_msg());
	
	INFOPRINTCOLOR(GY_COLOR_GREEN, "%s\n", print_msg2().buffer());

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Using get_buf() : %s\n\n", print_msg({get_buf().get(), 512}));

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Using get_buf2() : %s\n\n", print_msg({get_buf2().data(), 512}));

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Using MCHAR_BUF print_msg3(&&) : %s\n\n", print_msg3(MCHAR_BUF<512>("Test String")));

	{
	INFOPRINTCOLOR(GY_COLOR_GREEN, "Testing NRVO using get_buf()...\n");

	auto buf2 = get_buf();

	GY_CC_BARRIER();

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Using saved buf2 : %s\n\n", print_msg({buf2.get(), 512}));
	}

	{
	INFOPRINTCOLOR(GY_COLOR_GREEN, "Using multiple get_buf()s : %s : %s\n\n", print_msg({get_buf().get(), 512}), print_msg({get_buf().get(), 512}));
	}	

	{
	INFOPRINTCOLOR(GY_COLOR_GREEN, "Using mtbl hash table...\n\n");
	mtbl.try_emplace(1, "using map");
	}	

	{
	MCHAR_BUF<512>		mchar;
	
	GY_CC_BARRIER();

	try {
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Checking exception and move handling with copy construct : %s : %s : %s\n\n", 
			print_except(MCHAR_BUF<512>()), print_except(MCHAR_BUF<512>(mchar)), print_except(MCHAR_BUF<512>(std::move(mchar))));
	}
	catch(std::exception & e) {
		INFOPRINTCOLOR(GY_COLOR_RED, "Caught exception : %s\n\n", e.what());
	}

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Exception test completed...\n\n");
	}

	{
	try {
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Checking exception and lref handling : %s\n\n", print_except(MCHAR_BUF<512>("Test lref").get_ref()));
	}
	catch(std::exception & e) {
		INFOPRINTCOLOR(GY_COLOR_RED, "Caught exception : %s\n\n", e.what());
	}

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Exception test completed...\n\n");
	}

	{
	try {
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Using MCHAR_BUF print_except(&&) : %s\n\n", print_except(MCHAR_BUF<512>("Except String")));
	}
	catch(std::exception & e) {
		INFOPRINTCOLOR(GY_COLOR_RED, "Caught exception : %s\n\n", e.what());
	}
	INFOPRINTCOLOR(GY_COLOR_GREEN, "Exception test completed...\n\n");
	}


	{
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Testing Copy Elision from shared_ptr...\n");

		auto		shr1 = std::make_shared<SHRWRAP>();
		gweakshr	= shr1;

		GY_CC_BARRIER();

		auto 		shr2 = get_shared();

		GY_CC_BARRIER();

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Shared Ptr data is %s\n", bool(shr2) && bool(shr2->shr_) ? shr2->shr_->get() : "No value");

	}	

	return 0;
}	

