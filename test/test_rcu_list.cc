//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include		"gy_rcu_inc.h"

using 			namespace gyeeta;

struct TEST_WRAP
{
	std::string	data;
	pid_t		last_pid_;
	uint64_t	clock_usec	{get_usec_clock()};

	TEST_WRAP() noexcept 				= default;

	TEST_WRAP(const char * str) : data(str), last_pid_(gy_gettid())
	{}

	TEST_WRAP(const TEST_WRAP &) 			= default;

	TEST_WRAP(TEST_WRAP &&) 			= default;

	TEST_WRAP & operator=(const TEST_WRAP &)	= default;

	TEST_WRAP & operator=(TEST_WRAP &&)		= default;

	~TEST_WRAP() 
	{
		last_pid_ = 0;
	}	
};

struct TEST_INLINE
{
	RCU_LIST_CLASS_MEMBERS();

	std::string	data;
	pid_t		last_pid_;
	uint64_t	clock_usec	{get_usec_clock()};

	TEST_INLINE() noexcept				= default;

	TEST_INLINE(const char * str) : data(str), last_pid_(gy_gettid())
	{}

	TEST_INLINE(const TEST_INLINE &) 		= default;

	TEST_INLINE(TEST_INLINE &&) 			= default;

	TEST_INLINE & operator=(const TEST_INLINE &)	= default;

	TEST_INLINE & operator=(TEST_INLINE &&)		= default;

	~TEST_INLINE() 
	{
		last_pid_ = 0;
	}	

	TEST_INLINE *get_data() noexcept
	{
		return this;
	}	
	
};

using WRAP_ELEM 	= RCU_LIST_WRAPPER <TEST_WRAP>;

using LIST_WRAP 	= RCU_LIST <WRAP_ELEM>;
using LIST_INLINE	= RCU_LIST <TEST_INLINE>;

int			to_exit = 0;

static void offline_if_one_lock()
{
	RCU_LOCK_SLOW	slowlock;
}	

template <typename T>
void * writer_thread(RCU_LIST <T> *plist)
{
	try {
		T		*pelem, *pelem2, *pdupelem;
		size_t		max_del_num = 0, currelem = 0;

		pelem 	= new T(" new test"); 
		pelem2 	= new T(*pelem);

		plist->insert_head(pelem);
		plist->insert_tail(pelem2);

		auto lbd = [&](T *pdatanode, void *arg) noexcept -> CB_RET_E
		{
			T 		newdata = *pdatanode;

			if (++currelem < max_del_num) {
				return CB_DELETE_ELEM;
			}
			return CB_OK;
		};

		auto constlam = [&](T *pdatanode, void *arg) noexcept -> CB_RET_E
		{
			T 		newdata = *pdatanode;

			asm("");

			if (++currelem < max_del_num) {
				return CB_OK;
			}
			return CB_BREAK_LOOP;
		};


		for (int j = 0; j < 10; j++) {
			for (int i = 0; i < 10000; i++) {
				pelem 	= new T(" new test 2"); 
				
				plist->insert_tail(pelem);
			}	

			gy_nanosleep(0, GY_NSEC_PER_MSEC * 2); 
			
			max_del_num = 1000;
			currelem = 0;

			plist->walk_list_to_delete(lbd);

			gy_nanosleep(0, GY_NSEC_PER_MSEC * 2); 

			for (int i = 0; i < 100; i++) {
				pelem 	= new T(" new test 3"); 
				
				plist->insert_tail(pelem);
			}	

			gy_nanosleep(0, GY_NSEC_PER_MSEC * 2); 

			max_del_num = 10000;
			currelem = 0;

			plist->template walk_list_const<decltype(constlam), RCU_LOCK_FAST>(constlam);

			currelem = 0;
			plist->walk_list_to_delete(lbd);

			gy_nanosleep(0, GY_NSEC_PER_MSEC * 2); 

			for (int i = 0; i < 1000; i++) {
				pelem 	= new T(" new test 4"); 
				
				plist->insert_head(pelem);
			}	

			gy_nanosleep(0, GY_NSEC_PER_MSEC * 2); 

			max_del_num = 10000000;
			currelem = 0;

			plist->template walk_list_to_delete<decltype(lbd), RCU_LOCK_FAST>(lbd);
			
			gy_thread_rcu().gy_rcu_thread_offline();

			for (int i = 0; i < 100; i++) {
				pelem 	= new T(" new test 5"); 
				
				plist->insert_tail(pelem);
			}

			gy_nanosleep(0, GY_NSEC_PER_MSEC * 2); 

			plist->clear_list();

			gy_nanosleep(0, GY_NSEC_PER_MSEC * 2); 

			for (int i = 0; i < 1000; i++) {
				pelem 	= new T(" new test 6"); 
				
				plist->insert_tail(pelem);
			}

			offline_if_one_lock();

			gy_nanosleep(1, 0);
		}
	}
	GY_CATCH_EXCEPTION(ERRORPRINT("Exception occured while inserting elements : %s\n", GY_GET_EXCEPT_STRING));

	return nullptr;
}	


template <typename T>
void * reader_thread(RCU_LIST <T> *plist)
{
	size_t		max_upd_num = 10000, currelem = 0;

	auto lbd = [&](T *pdatanode, void *arg) noexcept -> CB_RET_E
	{
		T 		newdata = *pdatanode;

		if (++currelem < max_upd_num) {
			pdatanode->get_data()->clock_usec = get_usec_clock();
		}
		return CB_OK;
	};

	auto constlam = [&](T *pdatanode, void *arg) noexcept -> CB_RET_E
	{
		T 		newdata = *pdatanode;

		asm("");

		return CB_OK;
	};

	using U = 	typename std::remove_reference<decltype(*plist)>::type;
	
	U 		tmplist(*plist), tmplist2;

	currelem = 0;
	tmplist2.walk_list_const(lbd);
	currelem = 0;
	tmplist.walk_list_const(lbd);
	
	tmplist2 = std::move(tmplist);

	tmplist += std::move(tmplist2);

	currelem = 0;
	tmplist2.walk_list_const(lbd);
	currelem = 0;
	tmplist.walk_list_const(lbd);
	
	while (to_exit == 0) {
		gy_nanosleep(0, GY_NSEC_PER_MSEC * 2); 
		
		max_upd_num = 1000;

		currelem = 0;
		plist->walk_list_to_delete(lbd);

		gy_nanosleep(0, GY_NSEC_PER_MSEC * 2); 

		max_upd_num = 10000;

		{
			RCU_DEFER_OFFLINE	slowlock;

			currelem = 0;
			plist->walk_list_const(constlam);

			currelem = 0;
			plist->walk_list_const(lbd);
		}

		gy_nanosleep(0, GY_NSEC_PER_MSEC * 2); 

		max_upd_num = 10000000;
		currelem = 0;

		plist->template walk_list_const<decltype(lbd), RCU_LOCK_FAST>(lbd);
		
		currelem = 0;
		plist->template walk_list_const<decltype(constlam), RCU_LOCK_FAST>(constlam);

		offline_if_one_lock();

		gy_nanosleep(1, 0);
	}

	return nullptr;
}	

void * rthread_wrap(void *arg)
{
	return reader_thread <WRAP_ELEM>((RCU_LIST<WRAP_ELEM> *)arg);
}	

void * rthread_in(void *arg)
{
	return reader_thread <TEST_INLINE>((RCU_LIST<TEST_INLINE> *)arg);
}	

void * wthread_wrap(void *arg)
{
	return writer_thread <WRAP_ELEM>((RCU_LIST<WRAP_ELEM> *)arg);
}	

void * wthread_in(void *arg)
{
	return writer_thread <TEST_INLINE>((RCU_LIST<TEST_INLINE> *)arg);
}	


int main(int argc, char **argv)
{
	gdebugexecn = 10;
	gyeeta::set_stdout_buffer_mode(false);

	INFOPRINTCOLOR(GY_COLOR_CLEAR_SCREEN, "\t\tStarting the RCU List test cases...\n\n\n");

	PROC_CPU_IO_STATS::init_singleton(5);	

	GY_SIGNAL_HANDLER::init_singleton(argv[0]);

	LIST_WRAP		glistwrap, gtestwrap, gmovtest;
	LIST_INLINE		glistinline;

	WRAP_ELEM		*pelem;
	TEST_INLINE		*pin;

	for (int i = 0; i < 100; ++i) {
		pelem = new WRAP_ELEM("test1");

		gtestwrap.insert_head(pelem);
	}

	glistwrap = gtestwrap;

	gmovtest = std::move(gtestwrap);

	int			ret;
	pthread_t		wrtid[3], rdtid[2];	
	pthread_t		wrtidin[3], rdtidin[2];	
	
	for (size_t i = 0; i < GY_ARRAY_SIZE(rdtid); ++i) {
		gy_create_thread(&rdtid[i], rthread_wrap, &glistwrap);
	}

	for (size_t i = 0; i < GY_ARRAY_SIZE(rdtidin); ++i) {
		gy_create_thread(&rdtidin[i], rthread_in, &glistinline);
	}

	for (size_t i = 0; i < GY_ARRAY_SIZE(wrtid); ++i) {
		gy_create_thread(&wrtid[i], wthread_wrap, &glistwrap);
	}

	for (size_t i = 0; i < GY_ARRAY_SIZE(wrtidin); ++i) {
		gy_create_thread(&wrtidin[i], wthread_in, &glistinline);
	}

	for (size_t i = 0; i < GY_ARRAY_SIZE(wrtid); ++i) {
		pthread_join(wrtid[i], nullptr);
	}	
	
	for (size_t i = 0; i < GY_ARRAY_SIZE(wrtidin); ++i) {
		pthread_join(wrtidin[i], nullptr);
	}	

	to_exit = 1;

	for (size_t i = 0; i < GY_ARRAY_SIZE(rdtid); ++i) {
		pthread_join(rdtid[i], nullptr);
	}	
	
	for (size_t i = 0; i < GY_ARRAY_SIZE(rdtidin); ++i) {
		pthread_join(rdtidin[i], nullptr);
	}	

	INFOPRINTCOLOR(GY_COLOR_BOLD_GREEN, "All threads exited. Waiting for RCU thread exit...\n");

	wait_for_all_call_rcu_free();

	return 0;
}
