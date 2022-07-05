
#include			"gy_common_inc.h"
#include			"gy_refcnt.h"

#include			"boost/intrusive_ptr.hpp"

using 				gyeeta::intrusive_ptr_add_ref;
using 				gyeeta::intrusive_ptr_release;

using namespace gyeeta;


struct Test1 : public INT_REF_CNT<gy_noatomic>
{
	SSO_STRING<128>			str_;
	uint64_t			cns_start_	{get_nsec_clock()};

	Test1(const char *str)
		: str_(str)
	{
		INFOPRINT("Test1 constructor called for pointer %p\n", this);
	}

	~Test1() noexcept
	{
		INFOPRINT("Test1 destructor called for pointer %p\n", this);
		cns_start_ = 0;
	}	
};



int main()
{
	boost::intrusive_ptr<Test1>	ob;

	{
		boost::intrusive_ptr<Test1>			bt(new Test1("Test string"));
		std::vector <boost::intrusive_ptr<Test1>> 	v0, v1;

		assert(1 == bt->intr_use_cnt());

		v0.emplace_back(bt);
		assert(2 == bt->intr_use_cnt());

		v1.emplace_back(v0[0]);
		assert(3 == bt->intr_use_cnt());

		ob = bt.get();
		assert(4 == ob->intr_use_cnt());

		ob.reset();
		assert(3 == bt->intr_use_cnt());

		auto b2 = std::move(bt);
		assert(3 == b2->intr_use_cnt());
		assert(false == bool(bt));

		ob = std::move(b2);
	}	

	assert(1 == ob->intr_use_cnt());
	ob.reset();
	
}
