//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include 		"gy_statistics.h"
#include 		"gy_stack_container.h"

using namespace gyeeta;

namespace gyeeta {

int						gdebugexecn = 10;	
bool						guse_utc_time = false, gunbuffered_stdout = false;
size_t		 				gpgsz_local_;
uint32_t 					gclktck_local_;

thread_local 	GY_THR_LOCAL			gthrdata_local_;
thread_local 	pid_t				gtid_local_ = -1, gtid_startpid_;

uint64_t					gproc_start_usec, gproc_start_clock, gproc_start_boot;
pid_t						gproc_start_pid, gproc_curr_pid;

GY_TIMEZONE* GY_TIMEZONE::get_singleton() noexcept	
{
	return nullptr;
}	

int gy_no_mutex_lock(GY_MUTEX * pmutex) noexcept
{
	return 0;
}	

int no_mutex_lock(pthread_mutex_t * pmutex) noexcept
{
	return 0;
}	

}

void * operator new(size_t count)
{
	auto ptr = std::malloc(count);

	INFOPRINTCOLOR(GY_COLOR_YELLOW, "malloc : Allocated %lu bytes Addr %p\n", count, ptr);

	return ptr;
}

void operator delete(void *ptr) noexcept
{
	INFOPRINTCOLOR(GY_COLOR_YELLOW, "free called for pointer %p\n", ptr);

	std::free(ptr);
}


uint32_t 		gret;

int test_prio_queue()
{
	struct test_data
	{
		char				str[128];
		double				pct;
		STR_ARRAY<128>			str2;

		test_data(double pctin) : pct(pctin)
		{
			snprintf(str, sizeof(str), "Percent %.03f%%", pctin);
			str2.strset(str);
		}

		test_data(test_data & other) : pct(other.pct), str2(other.str2)
		{
			strcpy(str, other.str);
		}	
		
		test_data(test_data && other) : pct(other.pct), str2(std::move(other.str2))
		{
			strcpy(str, other.str);
		}	

		test_data & operator= (const test_data & other)
		{
			strcpy(str, other.str);
			pct = other.pct;
			str2 = other.str2;

			return *this;
		}	

		test_data & operator= (test_data && other)
		{
			strcpy(str, other.str);
			pct = other.pct;
			str2 = std::move(other.str2);

			return *this;
		}
	};

	struct test_comparator 
	{
		bool operator() (const test_data & lhs, const test_data & rhs) const noexcept
		{
			return lhs.pct > rhs.pct;
		}	
	};

	using PRIO_VEC			= GY_STACK_VECTOR<test_data, sizeof(test_data) * (10)>;
	using PRIO_ARENA		= PRIO_VEC::allocator_type::arena_type;

	using prio_queue 		= BOUNDED_PRIO_QUEUE<test_data, test_comparator, NULL_MUTEX, PRIO_VEC>;

	PRIO_ARENA			arena;
	prio_queue			prio(10, arena);

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Initial prio size = %lu. Now starting test...\n", prio.size());
	
	for (int i = 0; i < 15; i++) {
		test_data		data(i);

		prio.push(std::move(data));
	}	

	for (int i = 10; i < 20; i++) {

		const auto compemp = [i](const test_data & elem) noexcept
		{
			return i > elem.pct;
		};

		prio.try_emplace(compemp, i);
	}	

	INFOPRINTCOLOR(GY_COLOR_GREEN, "After init push prio size = %lu. Now starting walk...\n", prio.size());

	auto walk = [](test_data & datanode, void *arg1, void *arg2) -> CB_RET_E { IRPRINT("Data : %s\n", datanode.str); return CB_OK;};

	prio.walk_queue(walk, nullptr, nullptr);	

	prio.clear();

	for (int i = 0; i < 10; i++) {
		test_data		data(i);

		prio.push(std::move(data));
	}	

	for (int i = 10; i < 40; i++) {

		const auto compemp = [i](const test_data & elem) noexcept
		{
			return i > elem.pct;
		};

		prio.try_emplace(compemp, i);
	}	

	INFOPRINTCOLOR(GY_COLOR_GREEN, "After clear and again push prio size = %lu. Now starting walk...\n", prio.size());

	prio.walk_queue(walk, nullptr, nullptr);	

	const auto remcb = [](const test_data & elem) noexcept
	{
		return elem.pct < 34;
	};	
	
	size_t nrem = prio.remove_elems(remcb);

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Now starting walk after removing %lu elems...\n", nrem);

	prio.walk_queue(walk, nullptr, nullptr);	

	prio.push(100);

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Now starting walk with queue sorted and push(100) ...\n");

	prio.walk_queue(walk, nullptr, nullptr, true);	

	prio.set_max_size(5);

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Now starting walk after queue reduction...\n");

	prio.walk_queue(walk, nullptr, nullptr);	

	prio.pop();
	prio.pop();

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Now starting walk after queue pop...\n");

	prio.walk_queue(walk, nullptr, nullptr);	

	auto prio2 = std::move(prio);

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Now starting walk after queue move to new object...\n");

	prio2.walk_queue(walk, nullptr, nullptr);	

	gret = 10;

	return 0;
}

int main(int argc, char **argv)
{
	gdebugexecn	= 10;

	test_prio_queue();

	return 0;
}	
