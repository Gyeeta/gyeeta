
#include		"gy_common_inc.h"
#include		"gy_rcu_inc.h"
#include		"gy_malloc_hook.h"

using namespace 	gyeeta;

void memuse(const char *prefix_str)
{
	GY_MALLOC_HOOK::gy_print_memuse(prefix_str, true);
}

std::atomic<uint32_t>		gnnews {0}, gndeletes {0};

class TEST_PID_COMM
{
public :	
	RCU_HASH_CLASS_MEMBERS(pid_t, TEST_PID_COMM);

	pid_t				pid_		{0};
	char				comm_[16]	{};

	TEST_PID_COMM(pid_t pid, const char * comm) noexcept 
		: pid_(pid)
	{
		GY_STRNCPY(comm_, comm, sizeof(comm_));
	}
	
	friend inline bool operator== (const TEST_PID_COMM & lhs, pid_t pid) noexcept
	{
		return lhs.pid_ == pid;
	}

	static void * operator new(size_t sz)
	{
		gnnews++;
		return ::operator new(sz);
	}

	static void operator delete(void * ptr, size_t sz) noexcept
	{
		gndeletes++;
		::operator delete(ptr);
	}
};	

using PID_COMM_TBL			= RCU_HASH_TABLE <pid_t, TEST_PID_COMM>;

int main()
{
	INFOPRINTCOLOR(GY_COLOR_YELLOW, "Testing RCU Hash Table Heap Memory use...\n\n");

	GY_MALLOC_HOOK::gy_malloc_init("Starting tests", true);

	{
		INFOPRINTCOLOR(GY_COLOR_BLUE, "Testing Hash Table Construction : ");

		PID_COMM_TBL			pidtbl(1);

		memuse("After pidtbl construction : ");
	}

	{
		memuse("After pidtbl destruction and before pidtbl 2 : ");

		PID_COMM_TBL			pidtbl2(1);

		memuse("After pidtbl2 construction : ");

		auto 		pelem1 = new TEST_PID_COMM(1111111, "Test 1111111");

		pidtbl2.insert_or_replace(pelem1, 1111111, get_int_hash(1111111));

		memuse("After pidtbl2 1 elem insert : ");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Inserting 256 elements and 8 duplicate elem which should be immediately frred into pidtbl2...\n\n");

		for (int i = 0; i < 256; ++i) {
			auto 		pelem = new TEST_PID_COMM(i, "Test");

			pidtbl2.insert_or_replace(pelem, i, get_int_hash(i));
		}	

		for (int i = 0; i < 8; ++i) {
			auto 		pelem = new TEST_PID_COMM(i, "Test");

			bool		bret = pidtbl2.insert_unique(pelem, i, get_int_hash(i), true /* delete_on_error */);

			assert(false == bret);
		}	

		memuse("After pidtbl2 256 elem insert and 8 duplicate inserts : ");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "pidtbl1 size is %lu....\n\n", pidtbl2.count_slow());
		
		pthread_yield();
		pthread_yield();

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Looking up the inserted 256 elements...\n\n");

		RCU_LOCK_SLOW			slowlock;

		for (int i = 0; i < 256; ++i) {
			auto		pelem = pidtbl2.lookup_single_elem_locked(i, get_int_hash(i));

			assert(pelem);
		}	

		slowlock.unlock();

		memuse("After pidtbl2 256 elem lookup : ");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Deleting 64 elements...\n\n");

		RCU_LOCK_SLOW			slowlock2;

		for (int i = 0; i < 64; ++i) {
			bool		bret = pidtbl2.delete_single_elem(i, get_int_hash(i));

			assert(bret);
		}	

		slowlock2.unlock();

		memuse("After pidtbl2 64 elem deletes : ");

	}

	memuse("After pidtbl2 destroy : ");

	{
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing RCU Hash Table with 32 fixed buckets and without auto_resize and auto_decrement to lessen memory use...\n\n");

		PID_COMM_TBL			pidtbl3(32, 1, 0, false, false);

		memuse("After pidtbl3 construction : ");

		auto 		pelem1 = new TEST_PID_COMM(1111111, "Test 1111111");

		pidtbl3.insert_or_replace(pelem1, 1111111, get_int_hash(1111111));

		memuse("After pidtbl3 1 elem insert : ");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Inserting 256 elements and 8 duplicate elem which should be immediately frred into pidtbl3...\n\n");

		for (int i = 0; i < 256; ++i) {
			auto 		pelem = new TEST_PID_COMM(i, "Test");

			pidtbl3.insert_or_replace(pelem, i, get_int_hash(i));
		}	

		for (int i = 0; i < 8; ++i) {
			auto 		pelem = new TEST_PID_COMM(i, "Test");

			bool		bret = pidtbl3.insert_unique(pelem, i, get_int_hash(i), true /* delete_on_error */);

			assert(false == bret);
		}	

		memuse("After pidtbl3 256 elem insert and 8 duplicate inserts : ");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "pidtbl1 size is %lu\n\n", pidtbl3.count_slow());

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Looking up the inserted 256 elements...\n\n");

		RCU_LOCK_SLOW			slowlock;

		for (int i = 0; i < 256; ++i) {
			auto		pelem = pidtbl3.lookup_single_elem_locked(i, get_int_hash(i));

			assert(pelem);
		}	

		slowlock.unlock();

		memuse("After pidtbl3 256 elem lookup : ");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Deleting 64 elements...\n\n");

		RCU_LOCK_SLOW			slowlock2;

		for (int i = 0; i < 64; ++i) {
			bool		bret = pidtbl3.delete_single_elem(i, get_int_hash(i));

			assert(bret);
		}	

		slowlock2.unlock();

		memuse("After pidtbl3 64 elem deletes : ");

	}

	{
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Fixed Bucket Table with 32 buckets mem usage...\n\n");

		PID_COMM_TBL			pidtbl4(32, 1, 0, false, false);

		memuse("After Table with 32 initial buckets construction : ");
	}

	{
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Fixed Bucket Table with 64 buckets mem usage...\n\n");

		PID_COMM_TBL			pidtbl4(64, 1, 0, false, false);

		memuse("After Table with 64 initial buckets construction : ");
	}

	{
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Fixed Bucket Table with 256 buckets mem usage...\n\n");

		PID_COMM_TBL			pidtbl4(256, 1, 0, false, false);

		memuse("After Table with 256 initial buckets construction : ");
	}

	{
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Fixed Bucket Table with 1024 buckets mem usage...\n\n");

		PID_COMM_TBL			pidtbl4(1024, 1, 0, false, false);

		memuse("After Table with 1024 initial buckets construction : ");
	}

	{
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Fixed Bucket Table with 1024 buckets max_buckets and 1 initial_bucket_size mem usage...\n\n");

		PID_COMM_TBL			pidtbl5(1, 1, 1024, false, false);

		memuse("After Table with 1024 max_buckets buckets construction : ");
	}

	{
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Fixed Bucket Table with 4096 buckets max_buckets and 1 initial_bucket_size mem usage with no preallocation...\n\n");

		PID_COMM_TBL			pidtbl5(1, 1, 4096, false, false);

		memuse("After Table with 4096 max_buckets buckets construction with no prealloc : ");
	}

	{
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Fixed Bucket Table with 4096 buckets max_buckets and 1 initial_bucket_size mem usage with preallocation...\n\n");

		PID_COMM_TBL			pidtbl5(1, 1, 4096, false, false, true);

		memuse("After Table with 4096 max_buckets buckets construction with prealloc : ");
	}

	{
		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing RCU Hash Table with 1024 max_buckets and 8 initial_bucket_size and no auto_decrement and no prealloc to lessen memory use...\n\n");

		PID_COMM_TBL			pidtbl3(8, 8, 1024, true, false);

		memuse("After pidtbl3 construction : ");

		auto 		pelem1 = new TEST_PID_COMM(1111111, "Test 1111111");

		pidtbl3.insert_or_replace(pelem1, 1111111, get_int_hash(1111111));

		memuse("After pidtbl3 1 elem insert : ");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Inserting 256 elements and 8 duplicate elem which should be immediately frred into pidtbl3...\n\n");

		for (int i = 0; i < 256; ++i) {
			auto 		pelem = new TEST_PID_COMM(i, "Test");

			pidtbl3.insert_or_replace(pelem, i, get_int_hash(i));
		}	

		for (int i = 0; i < 8; ++i) {
			auto 		pelem = new TEST_PID_COMM(i, "Test");

			bool		bret = pidtbl3.insert_unique(pelem, i, get_int_hash(i), true /* delete_on_error */);

			assert(false == bret);
		}	

		INFOPRINTCOLOR(GY_COLOR_CYAN, "pidtbl3 size is %lu\n\n", pidtbl3.count_slow());

		pthread_yield();
		pthread_yield();

		memuse("After pidtbl3 256 elem insert and 8 duplicate inserts : ");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Looking up the inserted 256 elements...\n\n");

		RCU_LOCK_SLOW			slowlock;

		for (int i = 0; i < 256; ++i) {
			auto		pelem = pidtbl3.lookup_single_elem_locked(i, get_int_hash(i));

			assert(pelem);
		}	

		slowlock.unlock();

		memuse("After pidtbl3 256 elem lookup : ");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Deleting 64 elements...\n\n");

		RCU_LOCK_SLOW			slowlock2;

		for (int i = 0; i < 64; ++i) {
			bool		bret = pidtbl3.delete_single_elem(i, get_int_hash(i));

			assert(bret);
		}	

		slowlock2.unlock();

		memuse("After pidtbl3 64 elem deletes : ");

	}

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Waiting for all call_rcu frees to complete...\n\n");

	wait_for_all_call_rcu_free();

	memuse("Before exit : ");

	INFOPRINTCOLOR(GY_COLOR_CYAN, "As per class new and delete operators : Total new calls %lu  : Total delete calls %lu\n\n", 
		gnnews.load(std::memory_order_relaxed), gndeletes.load(std::memory_order_relaxed));

	assert(gnnews.load(std::memory_order_relaxed) == gndeletes.load(std::memory_order_relaxed));
}	


#if 0

Breakpoint 2, my_malloc_hook (size=656, caller=0x48f919 <alloc_cds_lfht+25>) at test2_rcu_hashtable.cc:38
38              __malloc_hook = old_malloc_hook;
(gdb) bt
#0  my_malloc_hook (size=656, caller=0x48f919 <alloc_cds_lfht+25>) at test2_rcu_hashtable.cc:38
#1  0x00007ffff4c69701 in __libc_calloc (n=<optimized out>, elem_size=<optimized out>) at malloc.c:3203
#2  0x000000000048f919 in __default_alloc_cds_lfht (mm=0x4b01a0 <cds_lfht_mm_order>, cds_lfht_size=656, max_nr_buckets=9223372036854775808, min_nr_alloc_buckets=1)
    at ../src/rculfhash-internal.h:172
#3  alloc_cds_lfht (min_nr_alloc_buckets=1, max_nr_buckets=9223372036854775808) at rculfhash-mm-order.c:80
#4  0x000000000048e570 in _cds_lfht_new (init_size=1, min_nr_alloc_buckets=1, max_nr_buckets=<optimized out>, flags=3, mm=<optimized out>, flavor=0x4af7e0 <urcu_qsbr_flavor>, attr=0x0)
    at rculfhash.c:1618
#5  0x0000000000414290 in cds_lfht_new_flavor (init_size=1, min_nr_alloc_buckets=1, max_nr_buckets=0, flags=3, flavor=0x4af7e0 <urcu_qsbr_flavor>, attr=0x0)
    at /opt/lib_install/userspace-rcu//include/urcu/rculfhash.h:183
#6  0x00000000004150b5 in gyeeta::RCU_HASH_TABLE<int, TEST_PID_COMM, std::default_delete<TEST_PID_COMM>, &TEST_PID_COMM::rcu_match, &TEST_PID_COMM::rcu_get_hash, &TEST_PID_COMM::rcu_set_hash, true>::init_new_table (this=0x7fffffffde80, initial_alloc_bucket_sizein=1, min_nr_alloc_bucketsin=1, max_nr_buckets_in=0, flagsin=3, presize_thr_attr=0x0, dealloc_attr_on_destroy_in=false)
    at ../..//common/gy_rcu_inc.h:2597
#7  0x0000000000414aa4 in gyeeta::RCU_HASH_TABLE<int, TEST_PID_COMM, std::default_delete<TEST_PID_COMM>, &TEST_PID_COMM::rcu_match, &TEST_PID_COMM::rcu_get_hash, &TEST_PID_COMM::rcu_set_hash, true>::RCU_HASH_TABLE (this=0x7fffffffde80, initial_bucket_size=1, min_buckets=1, is_table_small=false, max_buckets=0, auto_resize=true, auto_decrement=true, presize_thr_attr=0x0,
    dealloc_attr_on_destroy=false) at ../..//common/gy_rcu_inc.h:1577
#8  0x00000000004139a1 in main () at test2_rcu_hashtable.cc:145
(gdb) c
Continuing.

Breakpoint 2, my_malloc_hook (size=2048, caller=0x48e7e6 <_cds_lfht_new+806>) at test2_rcu_hashtable.cc:38
38              __malloc_hook = old_malloc_hook;
(gdb) bt
#0  my_malloc_hook (size=2048, caller=0x48e7e6 <_cds_lfht_new+806>) at test2_rcu_hashtable.cc:38
#1  0x00007ffff4c69701 in __libc_calloc (n=<optimized out>, elem_size=<optimized out>) at malloc.c:3203
#2  0x000000000048e7e6 in alloc_split_items_count (ht=0x7a6030, ht=0x7a6030) at rculfhash.c:685
#3  _cds_lfht_new (init_size=1, min_nr_alloc_buckets=<optimized out>, max_nr_buckets=<optimized out>, flags=3, mm=<optimized out>, flavor=0x4af7e0 <urcu_qsbr_flavor>, attr=0x0) at rculfhash.c:1626
#4  0x0000000000414290 in cds_lfht_new_flavor (init_size=1, min_nr_alloc_buckets=1, max_nr_buckets=0, flags=3, flavor=0x4af7e0 <urcu_qsbr_flavor>, attr=0x0)
    at /opt/lib_install/userspace-rcu//include/urcu/rculfhash.h:183
#5  0x00000000004150b5 in gyeeta::RCU_HASH_TABLE<int, TEST_PID_COMM, std::default_delete<TEST_PID_COMM>, &TEST_PID_COMM::rcu_match, &TEST_PID_COMM::rcu_get_hash, &TEST_PID_COMM::rcu_set_hash, true>::init_new_table (this=0x7fffffffde80, initial_alloc_bucket_sizein=1, min_nr_alloc_bucketsin=1, max_nr_buckets_in=0, flagsin=3, presize_thr_attr=0x0, dealloc_attr_on_destroy_in=false)
    at ../..//common/gy_rcu_inc.h:2597
#6  0x0000000000414aa4 in gyeeta::RCU_HASH_TABLE<int, TEST_PID_COMM, std::default_delete<TEST_PID_COMM>, &TEST_PID_COMM::rcu_match, &TEST_PID_COMM::rcu_get_hash, &TEST_PID_COMM::rcu_set_hash, true>::RCU_HASH_TABLE (this=0x7fffffffde80, initial_bucket_size=1, min_buckets=1, is_table_small=false, max_buckets=0, auto_resize=true, auto_decrement=true, presize_thr_attr=0x0,
    dealloc_attr_on_destroy=false) at ../..//common/gy_rcu_inc.h:1577
#7  0x00000000004139a1 in main () at test2_rcu_hashtable.cc:145
(gdb) f 2
#2  0x000000000048e7e6 in alloc_split_items_count (ht=0x7a6030, ht=0x7a6030) at rculfhash.c:685
685                     ht->split_count = calloc(split_count_mask + 1,
(gdb) p split_count_mask
$1 = 15
(gdb) p sizeof(struct ht_items_count)
$2 = 128
(gdb) p 127 * sizeof(struct ht_items_count)
$5 = 16256
(gdb) c
Continuing.

Breakpoint 2, my_malloc_hook (size=16, caller=0x48f8ce <cds_lfht_alloc_bucket_table+110>) at test2_rcu_hashtable.cc:38
38              __malloc_hook = old_malloc_hook;
(gdb) bt
#0  my_malloc_hook (size=16, caller=0x48f8ce <cds_lfht_alloc_bucket_table+110>) at test2_rcu_hashtable.cc:38
#1  0x00007ffff4c69701 in __libc_calloc (n=<optimized out>, elem_size=<optimized out>) at malloc.c:3203
#2  0x000000000048f8ce in cds_lfht_alloc_bucket_table (ht=0x7a6030, order=<optimized out>) at rculfhash-mm-order.c:30
#3  0x000000000048e615 in cds_lfht_alloc_bucket_table (order=0, ht=0x7a6030) at rculfhash.c:893
#4  cds_lfht_create_bucket (size=1, ht=0x7a6030) at rculfhash.c:1510
#5  _cds_lfht_new (init_size=1, min_nr_alloc_buckets=<optimized out>, max_nr_buckets=<optimized out>, flags=3, mm=<optimized out>, flavor=0x4af7e0 <urcu_qsbr_flavor>, attr=0x0) at rculfhash.c:1631
#6  0x0000000000414290 in cds_lfht_new_flavor (init_size=1, min_nr_alloc_buckets=1, max_nr_buckets=0, flags=3, flavor=0x4af7e0 <urcu_qsbr_flavor>, attr=0x0)
    at /opt/lib_install/userspace-rcu//include/urcu/rculfhash.h:183
#7  0x00000000004150b5 in gyeeta::RCU_HASH_TABLE<int, TEST_PID_COMM, std::default_delete<TEST_PID_COMM>, &TEST_PID_COMM::rcu_match, &TEST_PID_COMM::rcu_get_hash, &TEST_PID_COMM::rcu_set_hash, true>::init_new_table (this=0x7fffffffde80, initial_alloc_bucket_sizein=1, min_nr_alloc_bucketsin=1, max_nr_buckets_in=0, flagsin=3, presize_thr_attr=0x0, dealloc_attr_on_destroy_in=false)
    at ../..//common/gy_rcu_inc.h:2597
#8  0x0000000000414aa4 in gyeeta::RCU_HASH_TABLE<int, TEST_PID_COMM, std::default_delete<TEST_PID_COMM>, &TEST_PID_COMM::rcu_match, &TEST_PID_COMM::rcu_get_hash, &TEST_PID_COMM::rcu_set_hash, true>::RCU_HASH_TABLE (this=0x7fffffffde80, initial_bucket_size=1, min_buckets=1, is_table_small=false, max_buckets=0, auto_resize=true, auto_decrement=true, presize_thr_attr=0x0,
    dealloc_attr_on_destroy=false) at ../..//common/gy_rcu_inc.h:1577
#9  0x00000000004139a1 in main () at test2_rcu_hashtable.cc:145
(gdb) c
Continuing.



#endif
