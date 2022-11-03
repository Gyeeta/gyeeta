//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_multi_proc_comm.h"

namespace gyeeta {

static MULTI_COMM_SINGLETON		*pgmultihdlr_ = nullptr;

MULTI_COMM_SINGLETON::MULTI_COMM_SINGLETON()
{
	decltype(pmulti4096_)		pmulti4096 = nullptr;
	decltype(psingle512_)	 	psingle512 = nullptr;
	decltype(psingle64_)	 	psingle64 = nullptr;
	
	pmulti4096		= MULTI_PROC_SZ_4096::allocate_handler();

	GY_SCOPE_EXIT {
		if (pmulti4096) MULTI_PROC_SZ_4096::deallocate_handler(pmulti4096);
	};
		
	psingle64		= SINGLE_PROC_SZ_64::allocate_handler();

	GY_SCOPE_EXIT {
		if (psingle64) SINGLE_PROC_SZ_64::deallocate_handler(psingle64);
	};

	psingle512		= SINGLE_PROC_SZ_512::allocate_handler();

	pmulti4096_ 		= std::exchange(pmulti4096, nullptr);
	psingle64_ 		= std::exchange(psingle64, nullptr);
	psingle512_ 		= std::exchange(psingle512, nullptr);
}		

MULTI_COMM_SINGLETON::MULTI_PROC_SZ_4096 * MULTI_COMM_SINGLETON::get_multi_4096() noexcept
{
	if (pgmultihdlr_) {
		return pgmultihdlr_->pmulti4096_;
	}	
	return nullptr;
}	


MULTI_COMM_SINGLETON::SINGLE_PROC_SZ_64 * MULTI_COMM_SINGLETON::get_single_64() noexcept
{
	if (pgmultihdlr_) {
		return pgmultihdlr_->psingle64_;
	}	
	return nullptr;
}	

MULTI_COMM_SINGLETON::SINGLE_PROC_SZ_512 * MULTI_COMM_SINGLETON::get_single_512() noexcept
{
	if (pgmultihdlr_) {
		return pgmultihdlr_->psingle512_;
	}	
	return nullptr;
}	

int MULTI_COMM_SINGLETON::init_singleton()
{
	int				texp = 0, tdes = 1;
	static std::atomic<int>		is_init_sched(0);

	if (false == is_init_sched.compare_exchange_strong(texp, tdes)) {
		return 0;
	}

	try {
		pgmultihdlr_	= new MULTI_COMM_SINGLETON();
	
		return 0;
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINT("Exception caught while creating multi comm singleton : %s\n", GY_GET_EXCEPT_STRING);
		throw;
	);
}

} // namespace gyeeta
	
