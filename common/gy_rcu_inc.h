
/*
 * Provides C++ wrappers for Userspace RCU liburcu (https://github.com/urcu/userspace-rcu) Hash Table and Circular Linked List 
 */ 

#pragma			once

#include 		"gy_common_inc.h"

/*

#	define 		GY_NO_LGPL 
 
 *
 * Uncomment the above line in case this code is to be used in a Non LGPL project...
 */
 
#ifndef 		GY_NO_LGPL
#	define		_LGPL_SOURCE 
#else
#	define		URCU_INLINE_SMALL_FUNCTIONS 
#endif

/*
 * RCU (Read-Copy-Update) is a synchronization mechanism enabling lock free reads with concurrent writes 
 * Refer to https://lwn.net/Articles/262464/
 * 
 * RCU can be thought of as analogous to a lightweight MVCC framework. 
 *
 * Different flavors of RCU exist as per the links mentioned below.
 * Note we are using as default the QSBR flavor (fastest flavor) of userspace RCU. 
 *
 * XXX : QSBR has a few strict requirements : 
 * Specifically, explicit calls to urcu_qsbr_quiescent_state(), or urcu_qsbr_thread_offline() and urcu_qsbr_thread_online() 
 * needed when the readers are not accessing the RCU protected resources
 * 
 * Refer to https://lwn.net/Articles/573424/ and https://lwn.net/Articles/573439/ for RCU APIs
 *
 * For RCU Hash Table APIs : https://lwn.net/Articles/573432/ and https://lwn.net/Articles/573431/
 * 
 * Also read : https://www.kernel.org/doc/Documentation/RCU/whatisRCU.txt and the excellent Perf Book :
 *
 * https://mirrors.edge.kernel.org/pub/linux/kernel/people/paulmck/perfbook/perfbook.2018.12.08a.pdf
 *
 * XXX : Please do not mix calls to call_rcu and subsequent fork() syscalls as the RCU fork 
 * handling is error prone. In case fork() is needed, please spawn a child process at init before any call_rcu
 * calls have been invoked and then let the child process spawn a grandchild. In fact, the thread_local gy_thread_rcu()
 * will be in an inconsistent state after fork() is done post object constructor. We do not handle any pthread_atfork() 
 * semantics here.
 */

/*
 * By default QSBR flavor of urcu is used. Define GY_URCU_FLAVOR in case other types need to be used before including this header
 *
 * This include file provides wrappers for base RCU mechanism as well as wrappers for RCU Intrusive List and RCU Intrusive Hash Table.
 */ 
#ifndef			GY_URCU_FLAVOR
#define 		GY_URCU_FLAVOR		urcu_qsbr_
#include 		"urcu/urcu-qsbr.h"
#endif

#include 		"urcu/rculfhash.h"
#include 		"urcu/rculist.h"	

#include 		"urcu/compiler.h"
#include		"jhash.h"

namespace gyeeta {

struct CALL_RCU_WRAP
{
	void			*pdata;
	struct rcu_head 	rcu_head_	{};

	CALL_RCU_WRAP(void *pdata = nullptr)  noexcept : pdata(pdata) 
	{}	
};	


template <typename T, class Deleter = std::default_delete<T>>
void gy_call_rcu_free_node_wrapper(struct rcu_head *phead) noexcept
{
	if (!phead) return;

	CALL_RCU_WRAP		*pdatanode = GY_CONTAINER_OF(phead, CALL_RCU_WRAP, rcu_head_);
	T			*pnode = static_cast<T *>(pdatanode->pdata);

	try {
		Deleter()(pnode);		
	}
	catch(...) {
	}	

	delete pdatanode;	// The datanode allocated with new
}

template <typename T, class Deleter = std::default_delete<T>>
void gy_call_rcu_free_node(struct rcu_head *phead) noexcept
{
	if (!phead) return;

	try {
		T		*pnode = GY_CONTAINER_OF(phead, T, rcu_head_);

		Deleter()(pnode);		
	}
	catch(...) {
	}	
}

/*
 * thread_local RCU class
 */ 
class RCU_THREAD_LOCAL
{
public :	
	pid_t			thrid_			{gy_get_thread_local().get_tid()};
	uint32_t		nreads_fast_		{0};
	bool			is_thread_online_	{true};
	bool			is_read_lock_		{false};
	bool			defer_offline_		{false};
	bool			is_walk_running_	{false};

	RCU_THREAD_LOCAL() noexcept
	{
		gy_get_thread_local().set_rcu(true);

		GY_CONCATENATE(GY_URCU_FLAVOR, register_thread());

		gy_rcu_thread_offline();

		CONDEXEC(
			DEBUGEXECN(11, INFOPRINTCOLOR(GY_COLOR_CYAN, "RCU Registration of thread %d done\n", thrid_););
		);
	}	

	RCU_THREAD_LOCAL(const RCU_THREAD_LOCAL & other) 		= 	delete;
	RCU_THREAD_LOCAL(RCU_THREAD_LOCAL && other) 			= 	delete;
	RCU_THREAD_LOCAL & operator= (const RCU_THREAD_LOCAL & other)	= 	delete;
	RCU_THREAD_LOCAL & operator= (RCU_THREAD_LOCAL && other)	= 	delete;

	~RCU_THREAD_LOCAL() noexcept
	{
		GY_CONCATENATE(GY_URCU_FLAVOR, unregister_thread());
	}	

	/*
	 * Returns true on successful urcu_qsbr_read_lock
	 * and false if already within RCU read lock.
	 * XXX Note although urcu_qsbr_read_lock() is itself recursive, currently we do not support recursive locking
	 */ 
	bool gy_rcu_read_lock_online() noexcept
	{
		if (is_thread_online_ == false) {
			GY_CONCATENATE(GY_URCU_FLAVOR, thread_online());
			is_thread_online_ = true;
		}
			
		if (is_read_lock_ == false) {	
			is_read_lock_ = true;
			GY_CONCATENATE(GY_URCU_FLAVOR, read_lock());

			nreads_fast_++;
			return true;
		}
		else {
			// Already in urcu_qsbr_read_lock
			return false;
		}	
	}
	
	/*
	 * Not recursive. Check return status of gy_rcu_read_lock_online() first...
	 */ 
	void gy_rcu_read_unlock_fast() noexcept
	{
		bool is_lock_with_walk = gy_read_unlock_check();

		if ((is_lock_with_walk == false) && (defer_offline_ == false) && (nreads_fast_ > 1000)) {
			nreads_fast_ = 0;

			GY_CONCATENATE(GY_URCU_FLAVOR, quiescent_state());
		}	
	}
		
	/*
	 * Will not consider RCU_DEFER_OFFLINE status
	 */
	void gy_rcu_quiescent_state() noexcept
	{
		if ((is_thread_online_ == true) && (false == is_rcu_walk_running())) {
			nreads_fast_ = 0;
			GY_CONCATENATE(GY_URCU_FLAVOR, quiescent_state());
		}
	}

	/*
	 * Use with caution as this function will offline the thread even though multiple 
	 * call frames may be in a RCU Read Lock. Only if a RCU walk is active, will the thread 
	 * remain in RCU Lock state. 
	 */
	void gy_rcu_thread_offline() noexcept	
	{
		if (is_thread_online_ == true) {
			bool 	is_lock_with_walk = gy_read_unlock_check();
		
			if ((is_lock_with_walk == false) && (defer_offline_ == false)) {	

				is_thread_online_ 	= false;
				nreads_fast_ 		= 0;

				GY_CONCATENATE(GY_URCU_FLAVOR, thread_offline());
			}
		}
		else {
			nreads_fast_ = 0;
		}	
	}		

	bool is_rcu_thread_offline() const noexcept
	{
		return !is_thread_online_;
	}	

	bool is_rcu_in_read_lock() const noexcept
	{
		return is_read_lock_;
	}	

	bool is_rcu_walk_running() const noexcept
	{
		return is_walk_running_;
	}	

	/* 
	 * Call the call_rcu_cb(phead) function asynchronously by passing to the call_rcu thread. 
	 * Can be used to delete the object containing the phead param as a field if call_rcu_cb = gy_call_rcu_free_node
	 *
	 * NOTE : The passed function (default being the object delete) will likely be called a few msec later
	 * 
	 * Also, call_rcu_cb(rcu_head *) MUST be noexcept
	 */
	template <typename T, class Deleter = std::default_delete<T>, void (*call_rcu_cb)(struct rcu_head *) = gy_call_rcu_free_node<T, Deleter>>
	void gy_call_rcu(struct rcu_head *phead) noexcept
	{
		bool		set_offline = false;

		if (is_thread_online_ == false) {
			GY_CONCATENATE(GY_URCU_FLAVOR, thread_online());
			is_thread_online_ = true;
			set_offline = true;
		}
		
		GY_CONCATENATE(GY_URCU_FLAVOR, call_rcu(phead, call_rcu_cb));

		if (set_offline) {
			GY_CONCATENATE(GY_URCU_FLAVOR, thread_offline());
			is_thread_online_ = false;
		}	
	}	
	

	/*
	 * Execute fcb() after synchronize_rcu() grace period completes.
	 * NOTE : This will block the calling thread for upto a few msec
	 * Also the calling thread must not be within an RCU walk lock
	 *
	 * Refer to https://lwn.net/Articles/573439/ for additional requirements for synchronize_rcu()
	 */
	template <typename FCB>
	void gy_synchronize_rcu(FCB & fcb) noexcept(noexcept(fcb()))
	{
		bool		to_lock = is_rcu_in_read_lock();
		bool 		is_lock_with_walk = gy_read_unlock_check();

		assert(is_lock_with_walk == false);
		
		if (is_lock_with_walk) {
			// No option but offlining the thread even at the cost of errors during the lock
			GY_CONCATENATE(GY_URCU_FLAVOR, thread_offline());
		}
			
		GY_CONCATENATE(GY_URCU_FLAVOR, synchronize_rcu());

		fcb();

		if (to_lock) {
			if (is_lock_with_walk) {
				GY_CONCATENATE(GY_URCU_FLAVOR, thread_online());
			}	
			is_read_lock_ = true;
			GY_CONCATENATE(GY_URCU_FLAVOR, read_lock());
		}	
	}

	/* 
	 * Delete pdata after synchronize_rcu() grace period completes
	 * NOTE : This will block the calling thread for upto a few msec
	 * Also the calling thread must not be within an RCU walk lock
	 *
	 * Refer to https://lwn.net/Articles/573439/ for additional requirements for synchronize_rcu()
	 */
	template <typename T, class Deleter = std::default_delete<T>>
	void gy_synchronize_rcu_delete(T *pdata) noexcept(std::is_nothrow_destructible<T>::value)
	{
		const auto lamdel = [pdata]() {
						if (pdata) {
							Deleter()(pdata);
						}
					};

		gy_synchronize_rcu(lamdel);
	}

	/* 
	 * Execute defer_rcu_cb(arg) asynchronously similar to call_rcu() if possible or under some circumstances 
	 * execute defer_rcu_cb(arg) synchronously after blocking for a grace period of a few msec.
	 * 
	 * NOTE : This is the fastest way to execute a function (defer_rcu_cb) compared to call_rcu() or synchronize_rcu() but 
	 * can block the calling thread sometimes...
	 *
	 * NOTE : The calling thread must not be within an RCU walk lock.
	 * Also, defer_rcu_cb(void *) MUST be noexcept
	 *
	 * Refer to https://lwn.net/Articles/573439/ for additional requirements for defer_rcu()
	 */
	void gy_defer_rcu(void (*defer_rcu_cb)(void *), void *arg) 
	{
		if (!defer_rcu_cb) {
			return;
		}

		bool		to_lock = is_rcu_in_read_lock();
		bool 		is_lock_with_walk = gy_read_unlock_check();

		assert(is_lock_with_walk == false);

		if (is_lock_with_walk) {
			// No option but offlining the thread even at the cost of errors during the lock
			GY_CONCATENATE(GY_URCU_FLAVOR, thread_offline());
		}
			
		GY_CONCATENATE(GY_URCU_FLAVOR, defer_rcu(defer_rcu_cb, arg));

		if (to_lock) {
			if (is_lock_with_walk) {
				GY_CONCATENATE(GY_URCU_FLAVOR, thread_online());
			}	
			is_read_lock_ = true;
			GY_CONCATENATE(GY_URCU_FLAVOR, read_lock());
		}	
	}	


	/*
	 * This method can be used to delete RCU protected pointers using the call_rcu mechanism 
	 * This needs an extra heap alloc per call but saves up on the blocking needed in case of gy_synchronize_rcu_delete()
	 *
	 * e.g. 
	 * 		TEST_RCU *pold = rcu_xchg_pointer(&test_rcu_pointer, pnew);
	 *
	 *		if (pold) gy_thread_rcu().gy_call_rcu_using_wrapper(pold);
	 *
	 * Here pold is deleted using the call_rcu wrapper which is freshly allocated (extra heap allocation).
	 */ 		
	template <typename T, class Deleter = std::default_delete<T>>
	void gy_call_rcu_using_wrapper(T *pclass)
	{
		CALL_RCU_WRAP		*pwrap;

		pwrap = new CALL_RCU_WRAP(static_cast<void *>(pclass));

		gy_call_rcu<T, Deleter, gy_call_rcu_free_node_wrapper<T, Deleter>>(&pwrap->rcu_head_);
	}	
	
	// Returns true if RCU walk is running and no unlock done. Returns false if RCU read unlocked
	bool gy_read_unlock_check() noexcept
	{
		if (is_read_lock_) {
			// rcu read unlock must not be called if a walk_hash_table/walk_list is running
			if (is_walk_running_) {
				return true;
			}	

			GY_CONCATENATE(GY_URCU_FLAVOR, read_unlock());
			is_read_lock_ = false;
		}

		return false;
	}											
};	

extern thread_local RCU_THREAD_LOCAL		grcu_thrdata_local_;
#define gy_thread_rcu()				gyeeta::grcu_thrdata_local_	

int rcu_send_async_destroy(struct cds_lfht *pht) noexcept;

/*
 * This function is not needed to be called but can be used to specify custom call_rcu thread params.
 * If not called, will be automatically called on first reclaim. Will throw an exception in case of 
 * malloc issue or failure to create pthread.
 */
static void gy_create_call_rcu_thread(bool is_rt_thread = false, int cpu_affinity = -1)
{
	auto 			pcallrcu = GY_CONCATENATE(GY_URCU_FLAVOR, create_call_rcu_data)(is_rt_thread ? URCU_CALL_RCU_RT : 0, cpu_affinity);

	if (!pcallrcu) {
		GY_THROW_SYS_EXCEPTION("Failed to create Call RCU Thread for RCU reclamation");
	}	
}	

static void ensure_rcu_registered() noexcept
{
	bool	is_offline = gy_thread_rcu().is_rcu_thread_offline();

	GY_CC_BARRIER();

	(void)is_offline;
}	

/*
 * Wait for all call_rcu frees to complete.
 * Must not be called from within an RCU read Lock
 */ 
static void wait_for_all_call_rcu_free(void) noexcept
{
	ensure_rcu_registered();

	GY_CONCATENATE(GY_URCU_FLAVOR, barrier());
}	

/*
 * QSBR flavor of RCU requires that the thread invoking RCU calls periodically call a Thread Offline function or a Thread Quiescence function
 * to enable the call_rcu Memory reclaimer thread(s) to reclaim memory by calling the destructor and delete. Other flavors of RCU do not
 * have this restriction and just need to call the RCU read lock/unlock.
 * QSBR flavor of RCU, in fact, has empty read lock/unlock routines and just relies on Offline/Quiescence for deletion and reclaim.
 *
 * Note : Thread Offline does not mean the thread is suspended. It just sets the Thread RCU state as offline and continues.
 *
 * There are 3 main RCU Read Lock types defined here :
 *
 * The slow version (RCU_LOCK_SLOW) will RCU Read unlock and offline the thread after scope exit
 * The Fast version (RCU_LOCK_FAST) will RCU Read unlock and queiescent the thread after 1000 fast operations.
 * The timed version (RCU_LOCK_TIMED) is like the fast version but if the unlock takes over 50 msec will offline the thread and 
 * queiescent the thread if the unlock takes over 20 msec
 *
 * The no chks version (RCU_LOCK_NO_CHKS) is the fastest with no checks done. WARNING : Use this only if you know what you are doing... 
 * This is to be used only for performance critical code where no conditional checks will be done as it will just RCU read unlock and return. 
 * It is highly recommended to use any of the 3 other locks specified instead of this one.
 *
 * RCU_DEFER_OFFLINE is NOT a RCU Lock. It just defers thread offlining till its scope end and so,
 * it can be used along with multiple RCU Lock operations and then offline the thread on scope exit, overriding
 * the thread offlining by intermediate RCU_LOCK_SLOW and others till the scope exit. 
 * 
 * Note : Thread Offline/Online operations are not cheap operations and so should be used judiciously...
 *
 * 			Guidelines for use :
 * 
 * 1. Unless you are sure, always prefer RCU_LOCK_SLOW. This is because the thread will be offlined on scope exit
 *    to enable the call_rcu thread to free up memory.
 *
 * 2. If calling multiple RCU hash table or RCU List calls within a loop, you may use RCU_DEFER_OFFLINE or any RCU Scope Lock before the Loop starts.
 *    This avoids the overhead of multiple RCU offline and then Online operations within the loop.
 *
 * 3. Do not mix calls to different lock types within a particular call frame. Only the first Lock call will be active as we do not recursively lock and 
 *    if the 1st call is a Fast Lock and a subsequent call is to a Slow type (before the Fast has been released), the slow lock will be ignored.
 *
 * NOTE : RCU Read lock is *NOT* a mutex. The same RCU Lock is applicable process wide across multiple
 * data structures. IOW, you could say there is a single RCU Lock process wide. In fact, for QSBR,
 * the rcu read lock and rcu read unlock are nops (i.e. empty functions) as QSBR relies just on
 * Quiescence or Offlining for reclaim.
 *
 * Multiple threads (including updaters) can be within RCU read lock simultaneously.
 *
 * As long as any thread is within a RCU read lock, the call_rcu thread (reclaimer thread) will have to wait to free up memory.
 * (The call_rcu will wait for 1 iteration of a barrier_wait for all active RCU readers to be quiesced or offlined).
 *
 * Also, an RCU Read Lock is not constrained to a single object. Any RCU read lock of any object type will cause the call_rcu
 * thread to wait for object destruction even though that object may be of a completely different class.
 */ 

/*
 * This RCU Scope Lock and will offline the thread after scope exit
 * Use this if there is only 1 RCU operation needed and then any subsequent RCU operation will likely
 * occur after some indeterminate time
 */
struct RCU_LOCK_SLOW
{
	RCU_LOCK_SLOW() noexcept : to_unlock(gy_thread_rcu().gy_rcu_read_lock_online()) 
	{}
	
	// This constructor can be used to change as per run time config from a slow unlock (offline) to fast (queiescent)
	explicit RCU_LOCK_SLOW(bool use_fast_unlock) noexcept 
		: to_unlock(
		({
			int tl = gy_thread_rcu().gy_rcu_read_lock_online();
			tl + tl * (int)use_fast_unlock;	// 1 + 1 = 2 for fast
		})
		)
	{}	

	~RCU_LOCK_SLOW() noexcept
	{
		unlock();
	}

	void unlock() noexcept
	{
		if (to_unlock) {
			if (to_unlock != 2) {
				to_unlock = 0;
				gy_thread_rcu().gy_rcu_thread_offline();
			}
			else {
				to_unlock = 0;
				gy_thread_rcu().gy_rcu_read_unlock_fast();
			}	
		}
	}	
	
	int		to_unlock;		
};	

/*
 * XXX Use with care with QSBR. Periodically use the RCU_LOCK_SLOW to
 * set the reader queiescent state or explicitly call gy_thread_rcu().gy_rcu_quiescent_state()
 * Also see comment above for slow.
 */ 
struct RCU_LOCK_FAST
{
	RCU_LOCK_FAST() noexcept : to_unlock(gy_thread_rcu().gy_rcu_read_lock_online()) 
	{}
	
	~RCU_LOCK_FAST() noexcept
	{
		unlock();
	}		

	void unlock() noexcept
	{
		if (to_unlock) {
			to_unlock = false;
			gy_thread_rcu().gy_rcu_read_unlock_fast();
		}	
	}	

	bool		to_unlock;		
};

/*
 * Like RCU_LOCK_FAST but also check time duration on scope end and if
 * time over 50 msec will offline the thread. If time taken is over 20 msec will queiescent.
 * 
 * Also see comment above for slow.
 */ 
struct RCU_LOCK_TIMED
{
	RCU_LOCK_TIMED() noexcept : tstartns((true == gy_thread_rcu().gy_rcu_read_lock_online()) ? get_nsec_clock() : 0) 
	{}
	
	~RCU_LOCK_TIMED() noexcept
	{
		unlock();
	}		

	/*
	 * Periodically check if quiesce needed (over 50 msec (not 20 msec) since last lock) and if so 
	 * will RCU unlock, quiesce and later reacquire lock
	 * Will ignore RCU_DEFER_OFFLINE
	 */
	bool check_current() noexcept
	{
		if (tstartns > 0) {
			uint64_t	currnsec = get_nsec_clock();
			int64_t 	tdiff = (int64_t)currnsec - tstartns;

			if (tdiff >= 50 * (int64_t)GY_NSEC_PER_MSEC) {

				tstartns = currnsec;

				gy_thread_rcu().gy_read_unlock_check();
				gy_thread_rcu().gy_rcu_quiescent_state();

				if (tdiff > 100 * (int64_t)GY_NSEC_PER_MSEC) {
					/*
					 * gy_rcu_quiescent_state() will result in a FUTEX_WAKE.
					 * Let the call_rcu thread take over as we have been within the RCU 
					 * lock section for quite a while...
					 */
					sched_yield();
				}

				currnsec = get_nsec_clock();
				gy_thread_rcu().gy_rcu_read_lock_online();

				return true;
			}
		}	
	
		return false;
	}

	void unlock() noexcept
	{
		if (tstartns > 0) {
			gy_thread_rcu().gy_rcu_read_unlock_fast();

			int64_t tdiff = (int64_t)get_nsec_clock() - tstartns;

			tstartns = 0;

			if (gy_thread_rcu().nreads_fast_ > 0) {
				if (50 * (int64_t)GY_NSEC_PER_MSEC <= tdiff) {
					/*GY_MT_COLLECT_PROFILE(100'000, "RCU Lock Time Took over 50 msec");*/

					gy_thread_rcu().gy_rcu_thread_offline();
				}
				else if (tdiff >= 20 * (int64_t)GY_NSEC_PER_MSEC) {
					/*GY_MT_COLLECT_PROFILE(100'000, "RCU Lock Time Took over 20 msec");*/

					gy_thread_rcu().gy_rcu_quiescent_state();
				}		
			}
		}	
	}

	int64_t 		tstartns;
};


/*
 * Calls rcu_read_lock/unlock directly without accessing gy_thread_rcu() and all other checks
 * XXX Use only if you know what you are doing...
 * Provides the best performance but no quiescent or offline done on scope exit
 */ 
struct RCU_LOCK_NO_CHKS
{
	RCU_LOCK_NO_CHKS() noexcept
	{
		GY_CONCATENATE(GY_URCU_FLAVOR, read_lock());
	}
	
	~RCU_LOCK_NO_CHKS() noexcept
	{
		GY_CONCATENATE(GY_URCU_FLAVOR, read_unlock());	
	}		
};	

/*
 * No Lock RCU Scoped Read Lock to be used for invocations of RCU Hash Table et al from within a call RCU thread as 
 * a Call RCU Thread cannot be within a RCU Read Lock section.
 * 
 * Example Usage : Deleting entries from hash table within a hash table. So the outer hash table desctructor gets invoked from
 * within a call rcu thread and to delete the inner hash table entries use this struct.
 */ 
struct RCU_NO_LOCK
{
	RCU_NO_LOCK() noexcept {}
	~RCU_NO_LOCK() noexcept {}
};
	
/* 
 * Use RCU_DEFER_OFFLINE to defer Thread Offline or Thread Quiescence till scope end. To be used in case multiple
 * RCU operations are expected after scope start and before scope end.
 * This is NOT a RCU Lock. Use appropriate RCU Lock after this scope start.
 */
struct RCU_DEFER_OFFLINE
{
	RCU_DEFER_OFFLINE() noexcept
	{
		if ((gy_thread_rcu().is_read_lock_ == false) && (gy_thread_rcu().defer_offline_ == false)) {
			gy_thread_rcu().defer_offline_ = true;
			to_unlock = 1;
		}	
	}

	// This constructor can be used to change as per run time config from a slower thread offline to a faster queiescent (if needed)
	explicit RCU_DEFER_OFFLINE(bool use_fast) noexcept 
		: to_unlock(
		({
			int		ret;

			if ((gy_thread_rcu().is_read_lock_ == false) && (gy_thread_rcu().defer_offline_ == false)) {
				gy_thread_rcu().defer_offline_ = true;

				ret = 1 + int(use_fast);	// 2 for fast queiescent
			}
			else {
				ret = 0;
			}

			ret;
		})
		)
	{}	
	
	RCU_DEFER_OFFLINE(bool use_timed, bool use_fast_if_not_timed) noexcept
	{
		if ((gy_thread_rcu().is_read_lock_ == false) && (gy_thread_rcu().defer_offline_ == false)) {
			gy_thread_rcu().defer_offline_ = true;

			if (use_timed) {
				to_unlock = get_nsec_clock();
			}
			else {
				to_unlock = 1 + int(use_fast_if_not_timed);
			}	
		}	
	}

	~RCU_DEFER_OFFLINE() noexcept
	{
		offline_now();
	}
	
	void offline_now() noexcept
	{
		if (to_unlock) {
			gy_thread_rcu().defer_offline_ = false;

			if (to_unlock == 1) {
				to_unlock = 0;
				gy_thread_rcu().gy_rcu_thread_offline();
			}
			else if (to_unlock == 2) {
				to_unlock = 0;
				gy_thread_rcu().gy_rcu_quiescent_state();
			}	
			else {
				int64_t tdiff = (int64_t)get_nsec_clock() - to_unlock;

				to_unlock = 0;

				if (50 * (int64_t)GY_NSEC_PER_MSEC <= tdiff) {
					gy_thread_rcu().gy_rcu_thread_offline();
				}
				else if (tdiff >= 20 * (int64_t)GY_NSEC_PER_MSEC) {
					gy_thread_rcu().gy_rcu_quiescent_state();
				}
			}	
		}	
	}

	int64_t			to_unlock	{0};		
};

// For Internal Use only. Not to be used by external users of this file
struct RCU_SET_WALK
{
	RCU_SET_WALK() noexcept 
	{
		if (gy_thread_rcu().is_walk_running_ == false) {
			gy_thread_rcu().is_walk_running_ = true;
			to_reset_ = true;
		}	
		else {
			to_reset_ = false;
		}	
	}	

	~RCU_SET_WALK() noexcept
	{
		if (to_reset_) {
			gy_thread_rcu().is_walk_running_ = false;
		}	
	}	

	bool		to_reset_	{false};
};	

/*
 * RCU List stuff follows :
 *
 * RCU List is a circular and intrusive linked list. No extra heap allocations are done while inserting into list.
 * The RCU List element needs to contain a few fields for List manipulation and the List element needs to be 
 * externally allocated.
 *
 * To use the RCU_LIST, the class T must contain some RCU specific fields. 2 methods to add these fields :
 *
 * 1. A wrapper class containing the actual T inline use the RCU_LIST_WRAPPER template as shown below :
 *
 * 	using 		TEST_ELEM_TYPE 		= RCU_LIST_WRAPPER <TEST_STRUCT>;
 * 
 * 	Here TEST_STRUCT is the main T class
 * 	TEST_ELEM_TYPE is the element type which will be inserted into the Linked List
 *
 * 2. To directly use the RCU List without defining any wrapper structs, please see comment of RCU_LIST_CLASS_MEMBERS below
 * 	(RCU_LIST_CLASS_MEMBERS needs to be called within the class declaration.)
 */
template <typename T>
class RCU_LIST_WRAPPER
{
public :	
	struct cds_list_head 		cds_node_;
	struct rcu_head 		rcu_head_;		// For call_rcu
	T				actdata_;

	template <class U = T, std::enable_if_t<std::is_default_constructible<U>::value, int> = 0>
	RCU_LIST_WRAPPER() noexcept(std::is_nothrow_default_constructible<T>::value)
	{}
		
	template <typename... _Args, std::enable_if_t<std::is_constructible<T, _Args&&...>::value, int> = 0>
	explicit RCU_LIST_WRAPPER(_Args && ...args) noexcept(std::is_nothrow_constructible<T, _Args&&...>::value)
		: actdata_(std::forward<_Args>(args)...)
	{}	 	

	template <typename U, typename... _Args, std::enable_if_t<std::is_constructible<T, std::initializer_list<U>, _Args&&...>::value, int> = 0>
	explicit RCU_LIST_WRAPPER(std::initializer_list<U> il, _Args && ...args) noexcept(std::is_nothrow_constructible<T, std::initializer_list<U>, _Args&&...>::value)
		: actdata_(il, std::forward<_Args>(args)...)
	{}	 	

	~RCU_LIST_WRAPPER() noexcept(std::is_nothrow_destructible<T>::value)							= default;

	RCU_LIST_WRAPPER(const RCU_LIST_WRAPPER & other) noexcept(std::is_nothrow_copy_constructible<T>::value)			= default;	

	RCU_LIST_WRAPPER(RCU_LIST_WRAPPER && other) noexcept(std::is_nothrow_move_constructible<T>::value)			= default;

	RCU_LIST_WRAPPER & operator= (const RCU_LIST_WRAPPER & other) noexcept(std::is_nothrow_copy_assignable<T>::value)	= default;	

	RCU_LIST_WRAPPER & operator= (RCU_LIST_WRAPPER && other) noexcept(std::is_nothrow_move_assignable<T>::value)		= default;
	
	T *get_data() noexcept
	{
		return &actdata_;
	}	

	const T * get_data() const noexcept
	{
		return &actdata_;
	}	

	T & get_ref() noexcept
	{
		return actdata_;
	}

	const T & get_ref() const noexcept
	{
		return actdata_;
	}	

	const T & get_cref() const noexcept
	{
		return actdata_;
	}	
};	

/* 
 * For classes not using the RCU_LIST_WRAPPER class, the class definition needs to call 
 * the RCU_LIST_CLASS_MEMBERS macro within the public access modifier section (at 
 * the start of the class declaration itself so that offsetof does not create any issues). 
 *
 * XXX It is essential that the RCU_LIST_CLASS_MEMBERS be the first defined field 
 * within the class declaration as offsetof macro is technically valid only on standard layout types.
 * (offsetof is used within the GY_CONTAINER_OF macro)...
 *
 * XXX Do not use this for Derived classes... For Derived classes, use the RCU_LIST_WRAPPER
 * g++ 6+ will not compile if this is used for a derived class as offsetof will fail.
 *
class MY_CLASS_C
{
public :
 	RCU_LIST_CLASS_MEMBERS();	

 	pid_t		pid;
 	char		procname[64];

 	MY_CLASS_C(pid_t pid, const char *pname);

	...
};
 *
 */ 

#define RCU_LIST_CLASS_MEMBERS()									\
	struct cds_list_head 		cds_node_ {nullptr, nullptr};					\
	struct rcu_head 		rcu_head_;


/*
 * 
 * The userspace Intrusive RCU Circular Linked List API Class : 
 *
 * Please refer to https://lwn.net/Articles/573441/ for more details
 *
 * Refer to test_rcu_list.cc for usage
 *
 * Use for a Multi Reader scenario as it provides Lock Free Reader.
 * Mutex Locking is done internally for adding or deleting elements. 
 *
 * Deleting elements uses the walk_list_locked() method. Users need to pass the callback which can be used to delete.
 * The walk_list_locked() will lock the  entire List while scanning each element although concurrent reads (walk_list_const()) are allowed. 
 * Please sparingly use this method.
 *
 * Note : This container is recommended if inserts/deletes constitute a much smaller % of the accesses and multiple
 * readers are concurrently accessing the list. 
 *
 * Also note that as the call_rcu mechanism is used for memory cleanup, the linked list elements will likely be deleted
 * after a delay of a few millisecs after the delete from the List itself. 
 * 
 * RCU List is a circular and intrusive linked list. No extra heap allocations are done while inserting into list.
 * The RCU List element needs to contain a few fields for List manipulation and the List element needs to be 
 * externally allocated.
 * 
 * Unlike Boost Intrusive, RCU List will call the std::default_delete<T> on element destruction to delete 
 * the element and reclaim memory. This can be overridden by specifying a custom Deleter template param.
 *
 * To use RCU List, we need to add RCU specific fields within the data structure element (T). This can be done
 * in 2 ways :
 *
 * 1. Use RCU_LIST_WRAPPER structure which will create a wrapper class containing T
 * 2. Add the RCU fields directly in your class definition using the macro RCU_LIST_CLASS_MEMBERS (This will only
 *    work for classes which are not derived).
 * 
 * Explanations of both these methods given above. See Comment for RCU_LIST_WRAPPER above...  
 *
 * If T contains a shared_ptr or a dynamically allocated variable, then on a list walk, the T data can be passed to child functions as a const reference,
 * as it is guaranteed that while the lookup is active the T element will not be deleted as RCU read lock is active.
 */ 

template <
	typename 			T, 
	class Deleter 			= std::default_delete<T>,	// On Elem Removal, the element will be deleted using delete
	void *(*NewOper)(size_t)	= operator new,			// Used to copy the list elements for Copy constructor/assignments
	void (*DelOper)(void *)		= operator delete		// Used to free elements allocated for Copy constructor/assignments on an exception
	>
class RCU_LIST
{
public :	
	struct cds_list_head		list_head_		{&list_head_, &list_head_};
	size_t				count_ 			{0};
	GY_MUTEX			mutex_;

	RCU_LIST() noexcept		= default;

	RCU_LIST(const RCU_LIST & other)
	{
		auto rcucopylambda = [](T *pdatanode, void *arg) -> CB_RET_E
		{
			RCU_LIST	*plist = static_cast<decltype(plist)>(arg);
			T		*pnewdatanode = static_cast<T *>((*NewOper)(sizeof(T)));
			
			try {
				new (pnewdatanode) T((const T &)(*pdatanode));
			}
			catch(...) {
				(*DelOper)(pnewdatanode);
				throw;
			}	

			plist->insert_tail(pnewdatanode);

			return CB_OK;
		};	

		copy_list<decltype(rcucopylambda)>(other, rcucopylambda);
	}	

	RCU_LIST(RCU_LIST && other) noexcept	
	{
		this->operator+= (std::move(other));
	}

	RCU_LIST & operator= (const RCU_LIST & other)	
	{
		if (this == &other) {
			return *this;
		}
			
		clear_list();
			
		auto rcucopylambda = [](T *pdatanode, void *arg) -> CB_RET_E
		{
			RCU_LIST		*plist = static_cast<decltype(plist)>(arg);
			T			*pnewdatanode = static_cast<T *>((*NewOper)(sizeof(T)));
			
			try {
				new (pnewdatanode) T((const T &)(*pdatanode));
			}	
			catch(...) {
				(*DelOper)(pnewdatanode);
				throw;
			}	

			plist->insert_tail(pnewdatanode);

			return CB_OK;
		};	

		copy_list<decltype(rcucopylambda)>(other, rcucopylambda);

		return *this;
	}	

	RCU_LIST & operator= (RCU_LIST && other) noexcept
	{
		if (this == &other) {
			return *this;
		}
			
		clear_list();	

		return this->operator+= (std::move(other));
	}		

	// Add the other list to the start of current list and then clear the other
	RCU_LIST & operator+= (RCU_LIST && other) noexcept
	{
		SCOPE_GY_MUTEX		smutex(&mutex_);

		cds_list_splice(&other.list_head_, &list_head_);
		count_ += other.count_;
	
		smutex.unlock();

		CDS_INIT_LIST_HEAD(&other.list_head_);
		other.count_ = 0;

		return *this;
	}		
	
	~RCU_LIST() noexcept
	{
		clear_list();
		CDS_INIT_LIST_HEAD(&list_head_);
	}

	
	/*
	 * Insert element at head of list
	 */ 
	void insert_head(T *pdata) noexcept
	{
		/*GY_MT_COLLECT_PROFILE(100'000, "RCU List insert head");*/

		if (!pdata) return;

		SCOPE_GY_MUTEX		smutex(&mutex_);

		cds_list_add_rcu(&pdata->cds_node_, &list_head_);
		count_++;
	}		
	
	/*
	 * Insert element at tail of list
	 */ 
	void insert_tail(T *pdata) noexcept
	{
		/*GY_MT_COLLECT_PROFILE(100'000, "RCU List insert tail");*/

		if (!pdata) return;

		SCOPE_GY_MUTEX		smutex(&mutex_);

		cds_list_add_tail_rcu(&pdata->cds_node_, &list_head_);
		count_++;
	}		

	/*
	 * List walker to be used to delete elements. Users need to define the following lambda which returns a CB_RET_E type.
	 * The lambda should return CB_OK in normal case, CB_DELETE_ELEM to delete the element and CB_BREAK_LOOP to break out of the walk.
	 *
	 * Please keep the walker lambda small as the walk is under rcu read lock as well as the mutex lock
	 *
	 * Lambda must be of type :
	 *
	 * Example :		auto glambda = [](GY_TEST_ELEM_TYPE *pdatanode, void *arg) noexcept -> CB_RET_E
				{
					char		buf[256];
					auto		psock = pdatanode->get_data(); 

					int 		ret = psock->do_something();

					if (ret < 0) {
						// Terminate loop
						return CB_BREAK_LOOP;
					}	
					else if (ret > 0) {
						// We want to delete these elems
						return CB_DELETE_ELEM; 
					}	
					
					// No delete here
					return CB_OK;
				};	
	 * 
	 * Returns number of elements walked in the list
	 */ 

	template <typename FCB, typename LockType = RCU_LOCK_SLOW>
	size_t walk_list_locked(FCB & walk, void *arg = nullptr) 
	{
		uint32_t			niters = 0, ndelelem = 0;
		T				*pdatanode, *ptmpnode;
		int				ret;
		CB_RET_E			cbret;
		struct rcu_head			*delarr[64];

		LockType			readlock;
		RCU_SET_WALK			setwalk;

		GY_SCOPE_EXIT {
			for (uint32_t i = 0; i < ndelelem; ++i) {
				gy_thread_rcu().gy_call_rcu<T, Deleter>(delarr[i]);
			}	
		};	

		SCOPE_GY_MUTEX		smutex(&mutex_);

		cds_list_for_each_entry_safe(pdatanode, ptmpnode, &list_head_, cds_node_) {

			++niters;

			cbret = walk(pdatanode, arg);

			if (cbret == CB_BREAK_LOOP) {
				break;
			}	
			else if (cbret == CB_DELETE_ELEM || cbret == CB_DELETE_BREAK) {
				cds_list_del_rcu(&pdatanode->cds_node_);
				count_--;

				if (ndelelem < GY_ARRAY_SIZE(delarr)) {
					delarr[ndelelem++] = &pdatanode->rcu_head_;
				}
				else {	
					gy_thread_rcu().gy_call_rcu<T, Deleter>(&pdatanode->rcu_head_);
				}

				if (cbret == CB_DELETE_BREAK) {
					break;
				}	
			}	
		}
		
		return niters;	
	}	


	/*
	 * List walker to be used to read/manipulate elements without deleting them.
	 * Use the same type of Lambda as walk_list_locked() but the lambda must not return CB_DELETE_ELEM
	 *
	 * Only RCU Read Locking used and no mutex locked...
	 *
	 * Returns number of elements walked in the list
	 */ 
	template <typename FCB, typename LockType = RCU_LOCK_SLOW>
	size_t walk_list_const(FCB & walk, void *arg = nullptr) const noexcept(noexcept(walk(nullptr, nullptr)))
	{
		uint32_t			niters = 0;
		int				ret;
		T				*pdatanode;
		CB_RET_E			cbret;

		LockType			readlock;
		RCU_SET_WALK			setwalk;
		
		cds_list_for_each_entry_rcu(pdatanode, &list_head_, cds_node_) {

			++niters;

			cbret = walk(pdatanode, arg);

			assert(cbret != CB_DELETE_ELEM && cbret != CB_DELETE_BREAK);
		
			if (cbret == CB_BREAK_LOOP) {
				break;
			}	
		}
		
		return niters;	
	}	

	void clear_list() noexcept
	{
		auto lbd = [](T *pdatanode, void *arg) noexcept -> CB_RET_E
		{
			return CB_DELETE_ELEM;
		};
		
		walk_list_locked(lbd);	
	}
		
	template <typename FCB>
	void copy_list(const RCU_LIST & other, FCB &copy)
	{
		/*GY_MT_COLLECT_PROFILE(1000, "RCU List copy");*/

		try {
			other.walk_list_const(copy, this);
		}
		catch(...) {
			clear_list();
			throw;
		}		
	}

	bool is_empty() const noexcept
	{
		return cds_list_empty(&list_head_);
	}	
		
	size_t size() const noexcept
	{
		return GY_READ_ONCE(count_);
	}	

	struct cds_list_head * get_list() noexcept
	{
		return &list_head_;
	}	
};
	
/*
 * Wrapper for a Pointer KeyType for RCU_HASH_TABLE
 */ 
template <typename T>
struct RCU_KEY_POINTER
{
	using U 		= typename std::remove_cv<T>::type;

	static_assert(std::is_pointer<typename std::remove_reference<U>::type>::value, "T must be a pointer type");

	const U			pdata;

	RCU_KEY_POINTER(const U pinput) noexcept : pdata(pinput) {}

	const U get_data() const noexcept 
	{
		return pdata;
	}

	uint32_t get_hash() const noexcept
	{
		return get_pointer_hash(pdata);
	}	
};

using RCU_KEY_CHAR_POINTER	= RCU_KEY_POINTER <const char *>;	


/*
 * RCU Hash Table stuff now follows... 
 *
 * RCU Hash Table is an intrusive Lock-Free Resizable Hash Table.
 * 
 * No extra heap allocations are done while inserting into the Hash Table.
 * The element to be inserted into the Table needs to contain a few fields for Table manipulation and the element needs to be 
 * externally allocated.
 *
 * Following 2 helper structs are to define wrapper classes encapsulating the actual data structure with
 * RCU Hash helper members. 
 * 
 * To use a wrapper class containing the actual T inline use the RCU_HASH_WRAPPER<Key, T> template as shown below :
 *
 * 	using 		GY_TEST_ELEM_TYPE 	= RCU_HASH_WRAPPER<INET_IP_PORT, INET_SOCK>;
	using 		GY_TEST_HASH_TABLE 	= RCU_HASH_TABLE<INET_IP_PORT, GY_TEST_ELEM_TYPE>;
 * 
 * Here INET_SOCK is the main T class and INET_IP_PORT is the Keytype
 * GY_TEST_ELEM_TYPE is the element type which will be inserted into the Hash Table GY_TEST_HASH_TABLE
 *
 * Users can create a wrapper encapsulating a pointer * of T data struct (externally allocated) as shown below :
 *
 * 	using 		GY_TEST_ELEM_TYPE 	= RCU_HASH_WRAP_PTR<INET_IP_PORT, INET_SOCK>;
	using 		GY_TEST_HASH_TABLE 	= RCU_HASH_TABLE<INET_IP_PORT, GY_TEST_ELEM_TYPE>;
 *
 * To use either wrapper, please define Valid Copy constructor and Assignment operator for
 * the actual class as well.
 *
 * To directly use the RCU Hash table without defining any wrapper structs, please see comment of RCU_HASH_CLASS_MEMBERS below
 * (RCU_HASH_CLASS_MEMBERS needs to be called within the class declaration.)
 *
 * Also implement an == operator method : T & == KeyType &
 *
 * Adds 40 bytes overhead to each class object.
 */ 	

template <typename KeyType, typename T>
class RCU_HASH_WRAPPER
{
public :	
	struct cds_lfht_node 		cds_node_		{};
	struct rcu_head 		rcu_head_		{};		// For call_rcu
	T				actdata_;
	uint64_t			hash_			{0};

	template <class U = T, std::enable_if_t<std::is_default_constructible<U>::value, int> = 0>
	RCU_HASH_WRAPPER() noexcept(std::is_nothrow_default_constructible<T>::value)
	{
		cds_lfht_node_init(&cds_node_);
	}
		
	template <typename... _Args, std::enable_if_t<std::is_constructible<T, _Args&&...>::value, int> = 0>
	explicit RCU_HASH_WRAPPER(_Args && ...args) noexcept(std::is_nothrow_constructible<T, _Args&&...>::value)
		: actdata_(std::forward<_Args>(args)...)
	{
		cds_lfht_node_init(&cds_node_);
	}	 	

	template <typename U, typename... _Args, std::enable_if_t<std::is_constructible<T, std::initializer_list<U>, _Args&&...>::value, int> = 0>
	explicit RCU_HASH_WRAPPER(std::initializer_list<U> il, _Args && ...args) noexcept(std::is_nothrow_constructible<T, std::initializer_list<U>, _Args&&...>::value)
		: actdata_(il, std::forward<_Args>(args)...)
	{
		cds_lfht_node_init(&cds_node_);
	}	 	

	~RCU_HASH_WRAPPER() noexcept(std::is_nothrow_destructible<T>::value)							= default;

	RCU_HASH_WRAPPER(const RCU_HASH_WRAPPER & other) noexcept(std::is_nothrow_copy_constructible<T>::value)			= default;

	RCU_HASH_WRAPPER(RCU_HASH_WRAPPER && other) noexcept(std::is_nothrow_move_constructible<T>::value)
		: cds_node_(other.cds_node_), rcu_head_(other.rcu_head_), actdata_(std::move(other.actdata_)), hash_(std::exchange(other.hash_, 0))
	{}	

	RCU_HASH_WRAPPER & operator= (const RCU_HASH_WRAPPER & other) noexcept(std::is_nothrow_copy_assignable<T>::value)	= default;

	RCU_HASH_WRAPPER & operator= (RCU_HASH_WRAPPER && other) noexcept(std::is_nothrow_move_assignable<T>::value)
	{
		if (this == &other) {
			return *this;
		}
		
		this->cds_node_	= other.cds_node_;
		this->rcu_head_ = other.rcu_head_;

		this->actdata_ 	= std::move(other.actdata_);
		this->hash_ 	= std::exchange(other.hash_, 0);

		return *this;
	}	
	
	T *get_data() noexcept
	{
		return &actdata_;
	}	

	const T * get_data() const noexcept
	{
		return &actdata_;
	}	

	T & get_ref() noexcept
	{
		return actdata_;
	}

	const T & get_ref() const noexcept
	{
		return actdata_;
	}

	const T & get_cref() const noexcept
	{
		return actdata_;
	}	
	
	uint64_t get_rcu_hash() const noexcept
	{
		return hash_;
	}	

	static inline void rcu_set_hash(RCU_HASH_WRAPPER *pwrap, uint64_t hashval) noexcept 
	{
		pwrap->hash_ = hashval;
	}	

	static inline uint64_t rcu_get_hash(RCU_HASH_WRAPPER *pwrap) noexcept 
	{
		return pwrap->hash_;
	}	

	static inline int rcu_match(struct cds_lfht_node *pht_node, const void *pkey) noexcept
	{
		RCU_HASH_WRAPPER 	*pwrap = GY_CONTAINER_OF(pht_node, RCU_HASH_WRAPPER, cds_node_);
		const T			*pactdata = &pwrap->actdata_;
		const KeyType		*pkeydata = static_cast<decltype(pkeydata)>(pkey);

		static_assert(noexcept((std::declval<T>() == std::declval<KeyType>())), "Operator == needs to be noexcept");

		return *pactdata == *pkeydata;
	}
};	
 
/*
 * See comment above. This class provides a pointer wrapper for your class to use the RCU_HASH_TABLE
 * Your class must provide a valid Copy & Assignment constructor and must implement an == operator method T & == KeyType &
 */ 
template <
	typename 	KeyType, 
	typename	T, 
	class 		Deleter 		= std::default_delete<T>,
	void * 		(*NewOper)(size_t)	= operator new,
	void 		(*DelOper)(void *)	= operator delete		// Used to free elements allocated for Copy constructor/assignments on an exception
	>
class RCU_HASH_WRAP_PTR
{
public :	
	struct cds_lfht_node 		cds_node_	{};
	struct rcu_head 		rcu_head_	{};			// For call_rcu
	T				*pactdata_	{nullptr};
	uint64_t			hash_		{0};

	RCU_HASH_WRAP_PTR() noexcept	= default;

	RCU_HASH_WRAP_PTR(T *pactdata) noexcept : pactdata_(pactdata)
	{
		cds_lfht_node_init(&cds_node_);
	}	 	

	~RCU_HASH_WRAP_PTR() noexcept(std::is_nothrow_destructible<T>::value)
	{
		if (pactdata_) {
			Deleter()(pactdata_);
		}	
	}	

	RCU_HASH_WRAP_PTR(RCU_HASH_WRAP_PTR && other) noexcept
		: cds_node_(other.cds_node_), rcu_head_(other.rcu_head_), pactdata_(std::exchange(other.pactdata_, nullptr)), 
		hash_(std::exchange(other.hash_, 0))
	{
		/*GY_MT_COLLECT_PROFILE(100'000, "RCU Hash wrap Pointer constructor");*/
	}	

	RCU_HASH_WRAP_PTR(const RCU_HASH_WRAP_PTR & other) 
		: cds_node_(other.cds_node_), rcu_head_(other.rcu_head_), hash_(other.hash_)
	{
		if (other.pactdata_) {
			pactdata_ = (T *)(*NewOper)(sizeof(T)); 

			try {
				new (pactdata_) T((const T &)*other.pactdata_);
			}
			catch(...) {
				(*DelOper)(pactdata_);
				throw;
			}	
		}	
		else pactdata_ = nullptr;
	}	

	RCU_HASH_WRAP_PTR & operator= (const RCU_HASH_WRAP_PTR & other)
	{
		if (this != &other) {
			this->cds_node_ = other.cds_node_;
			this->rcu_head_ = other.rcu_head_;

			if (pactdata_) {
				Deleter()(pactdata_);
			}	

			if (other.pactdata_) {
				pactdata_ = (T *)(*NewOper)(sizeof(T)); 

				try {
					new (pactdata_) T((const T &)*other.pactdata_);
				}
				catch(...) {
					(*DelOper)(pactdata_);
					throw;
				}	
			}	
			else pactdata_ = nullptr;

			this->hash_ = other.hash_;
		}
		return *this;
	}
		
	RCU_HASH_WRAP_PTR & operator= (RCU_HASH_WRAP_PTR && other) noexcept(std::is_nothrow_destructible<T>::value)
	{
		if (this == &other) {
			return *this;
		}
		
		cds_node_ = other.cds_node_;
		rcu_head_ = other.rcu_head_;

		if (pactdata_) {
			Deleter()(pactdata_);
		}	
		
		pactdata_ = std::exchange(other.pactdata_, nullptr);
		hash_ = std::exchange(other.hash_, 0);
		
		return *this;
	}	
	

	T *get_data() noexcept
	{
		return pactdata_;
	}	

	const T *get_data() const noexcept
	{
		return pactdata_;
	}	

	uint64_t get_rcu_hash() const noexcept
	{
		return hash_;
	}	

	static inline void rcu_set_hash(RCU_HASH_WRAP_PTR *pwrap, uint64_t hashval) noexcept
	{
		pwrap->hash_ = hashval;
	}	

	static inline uint64_t rcu_get_hash(RCU_HASH_WRAP_PTR *pwrap) noexcept
	{
		return pwrap->hash_;
	}	

	static inline int rcu_match(struct cds_lfht_node *pht_node, const void *pkey) noexcept
	{
		RCU_HASH_WRAP_PTR 		*pwrap = GY_CONTAINER_OF(pht_node, RCU_HASH_WRAP_PTR, cds_node_);
		const T				*pactdata = pwrap->pactdata_;
		const KeyType			*pkeydata = static_cast<decltype(pkeydata)>(pkey);

		static_assert(noexcept((std::declval<T>() == std::declval<KeyType>())), "Operator == needs to be noexcept");

		return (pactdata && (*pactdata == *pkeydata));
	}
};

/* 
 * For classes not using the RCU_HASH_WRAP_* class, the class definition needs to call 
 * the RCU_HASH_CLASS_MEMBERS macro within the public access modifier section (at 
 * the start of the class declaration itself so that offsetof does not create any issues). 
 *
 * XXX It is essential that the RCU_HASH_CLASS_MEMBERS be the first defined field 
 * within the class declaration as offsetof macro is technically valid only on standard layout types.
 * (offsetof is used within the GY_CONTAINER_OF macro)...
 *
 * XXX Do not use this for Derived classes... For Derived classes, use the RCU_HASH_WRAP_*
 * g++ 6+ will not compile if this is used for a derived class as offsetof will fail.
 *
 * This macro will define the cds_node_, rcu_head_ and hash_num fields and will define
 * static methods for rcu_match(), rcu hash get() and set().
 *
 * For e.g. 
 *
class MY_CLASS_C
{
public :
 	RCU_HASH_CLASS_MEMBERS(pid_t, MY_CLASS_C);		// pid_t is the keytype of the RCU Hash Table

 	pid_t		pid;
 	char		procname[64];

 	MY_CLASS_C(pid_t pid, const char *pname);

  	friend bool operator== (const MY_CLASS_C & lhs, const pid_t & pid) noexcept
	{
		return lhs.pid == pid;
	}

	...
};
 *
 * In addition to adding the RCU_HASH_CLASS_MEMBERS, users need to define an == operator
 * between the class object and the keytype object as shown above. 
 *
 * Also please define Valid Copy constructor, Assignment operator and optional Move constructor for the class as well.
 *
 * Adds 40 bytes overhead to each class object.
 *
 * If more than 1 field is to be used as the Key to the Hash Table (different tables), users can declare the 
 * RCU_HASH_CLASS_MEMBERS() for the first key type and then define the rcu_match function inline within the class definition 
 * for the other key types and then use that static function as the MatchFP template parameter.
 */ 
#define RCU_HASH_CLASS_MEMBERS(_keytype, _class_name)											\
																	\
	struct cds_lfht_node 		cds_node_ 	{};										\
	struct rcu_head 		rcu_head_	{};										\
	uint64_t			hash_field_ 	{0};										\
																	\
	uint64_t get_rcu_hash() const noexcept												\
	{																\
		return hash_field_;													\
	}																\
																	\
	static inline int rcu_match(struct cds_lfht_node *pht_node, const void *pkey) noexcept						\
	{																\
		const _class_name	*pactdata = GY_CONTAINER_OF(pht_node, _class_name, cds_node_);					\
		const _keytype		*pkeydata = static_cast<decltype(pkeydata)>(pkey);						\
																	\
		static_assert(noexcept((std::declval<_class_name>() == std::declval<_keytype>())), "Operator == needs to be noexcept");	\
																	\
		return *pactdata == *pkeydata;												\
	}																\
																	\
	static inline void rcu_set_hash(_class_name *pobj, uint64_t hashval) noexcept							\
	{																\
		pobj->hash_field_ = hashval;												\
	}																\
																	\
	static inline uint64_t rcu_get_hash(_class_name *pobj) noexcept									\
	{																\
		return pobj->hash_field_;												\
	}											



typedef int 			(*RCU_MATCH_CB)(struct cds_lfht_node *, const void *);

/*
 * The userspace RCU hash table API Class : Lock-Free Resizable RCU Hash Table
 *
 * RCU Hash Table is an Intrusive Lock-Free Resizable Hash Table. The element type T * to be inserted needs to be
 * allocated externally using a heap alloc. The key is not stored within the table and so can be stack allocated.
 * Unlike Boost Intrusive, this Hash Table will call the std::default_delete<T> on element destruction to delete 
 * the element and reclaim memory. This can be overridden by specifying a custom Deleter template param.
 * 
 * It is assumed the T type has the relevant fields within it to do a key comparison.
 *
 * Please refer to https://lwn.net/Articles/573432/ and https://lwn.net/Articles/573431/ for more details
 *
 * Refer to test_rcu_hashtable.cc for usage
 *
 * Use for multi reader concurrent mutex lock free access cases. 
 * XXX For multiple writers, an external mutex must be used to prevent concurrent updates to the same T element. 
 * Multiple writers adding deleting separate elements do not need to use an external mutex...
 * 
 * If T contains a shared_ptr or a unique_ptr, then on a lookup, the T.get() pointer can be passed to other functions
 * as long as the RCU Read lock is active as it is guaranteed that the T element will not be destroyed even if 
 * concurrently deleted as RCU read lock is active.
 *
 * Note : This container is recommended if inserts/deletes constitute a smaller % of the Hash table accesses and multiple
 * readers are concurrently accessing the table with a single updater. Using RCU primitives, allows block free reads along 
 * with a single write. 
 *
 * Note that as the call_rcu mechanism is used for memory cleanup, the hash table elements will likely be destroyed and 
 * deallocated after a delay of a few millisecs after the delete from the Hash table itself. 
 * 
 * The element to be inserted into the Table needs to contain a few RCU specific fields and the element needs to be 
 * heap allocated.
 *
 * We need to add RCU specific fields of 40 bytes within the data structure T. IOW, overhead of 40 bytes per T object. 
 * This can be done in 3 ways :
 *
 * 1. Use RCU_HASH_WRAPPER structure which will create a wrapper class containing T (inline)
 * 2. Use RCU_HASH_WRAP_PTR class which will create a wrapper containing a pointer to T (externally heap allocated)
 * 3. Add the RCU fields directly in your class definition using the macro RCU_HASH_CLASS_MEMBERS (This will only
 *    work for classes which are not derived).
 * 
 * Explanations of all 3 methods given above. See Comment for RCU_HASH_WRAPPER above...  
 *
 */ 
template <
	typename 	KeyType, 
	typename 	T, 
	class 		Deleter 						= std::default_delete<T>,	// On Elem Removal, the element will be deleted using delete
	int 		(*MatchFP)(struct cds_lfht_node *, const void *) 	= T::rcu_match, 		// Used for the T & == Key & comparison
	uint64_t 	(*HashGetFP)(T *) 					= T::rcu_get_hash,		// Get stored Hash Key
	void 		(*HashSetFP)(T *, uint64_t) 				= T::rcu_set_hash,		// Set Element Hash Key
	void *		(*NewOper)(size_t)					= operator new,			// Used to alloc elements for Copy constructor/Assignment
	void 		(*DelOper)(void *)					= operator delete		// Used to free elements allocated for Copy constructor/assignments on an exception
	>
class RCU_HASH_TABLE
{
protected :	
	struct cds_lfht 		*phtable_ 				{nullptr};
	uint32_t			initial_alloc_bucket_size_ 		{0}; 
	uint32_t			min_nr_alloc_buckets_ 			{0};
	uint32_t			max_nr_buckets_ 			{0};
	int				flags_ 					{0};
	mutable gy_atomic<int64_t>	approxcount_ 				{0};
	pthread_attr_t 			*presize_thr_attr_ 			{nullptr};
	bool				dealloc_attr_on_destroy_	 	{false};

public :	
	/*
	 * Constructor arguments (Refer to https://lwn.net/Articles/573432/ for details) :
	 * 
	 * initial_bucket_size 		=> Specifies the number of hash buckets to allocate initially : Min 1
	 *
	 * min_buckets			=> Specifies the minimum number of hash buckets : Default is 1 bucket
	 *
	 * max_buckets			=> Specifies the maximum number of hash buckets : Default is 0 i.e. unlimited. 
	 *
	 * auto_resize			=> Automatically resize the hash table on adding new elements. If false, will result in chaining.
	 *				auto_resize if true and auto_decrement if false can result in large memory usage if max_buckets == 0
	 *				as table will not shrink. Limit max_buckets to a max value in that case...
	 *
	 * auto_decrement		=> Enable Table auto shrink by maintaining counts of the number of nodes.
	 *				[WARN]: auto_decrement if true will result in min 1KB+ memory allocation which will increase with increased CPU count
	 *				Will use approx 1KB for every 4 CPU cores on host... 
	 *				Specify true only for large tables. For smaller tables (upto 1024 elems),
	 *				it is better to set an initial_bucket_size (say 32), limit max_buckets to say 1024 and auto_resize as true and 
	 *				auto_decrement false to save on memory.
	 *
	 * prealloc_buckets		=> Default false. If true and max_buckets > 0, will allocate the max_buckets in the constructor itself
	 *
	 * presize_thr_attr		=> If auto_resize, one or more resize table threads may be created. Specify this attr if special pthread attributes needed.
	 * dealloc_attr_on_destroy	=> Specify as false, if the presize_thr_attr is to be reused later					
	 */
	RCU_HASH_TABLE(uint32_t initial_bucket_size = 1, uint32_t min_buckets = 1, uint32_t max_buckets = 0, bool auto_resize = true, bool auto_decrement = true, \
					bool prealloc_buckets = false, pthread_attr_t *presize_thr_attr = nullptr, bool dealloc_attr_on_destroy = false) 

		: presize_thr_attr_(presize_thr_attr), dealloc_attr_on_destroy_(dealloc_attr_on_destroy)
	{
		if (auto_resize) {
			flags_ = CDS_LFHT_AUTO_RESIZE;
		}

		if (auto_decrement && (max_buckets == 0 || max_buckets > 1024)) {
			flags_ |= CDS_LFHT_ACCOUNTING;
		}
		
		initial_alloc_bucket_size_ 	= gy_round_up_to_power_of_2(initial_bucket_size);
		min_nr_alloc_buckets_ 		= gy_round_up_to_power_of_2(min_buckets);
		max_nr_buckets_ 		= gy_round_up_to_power_of_2(max_buckets);

		if (initial_alloc_bucket_size_ == 0) {
			initial_alloc_bucket_size_ = 1;
		}	
		if (min_nr_alloc_buckets_ == 0) {
			min_nr_alloc_buckets_ = 1;
		}	

		if (min_nr_alloc_buckets_ > initial_alloc_bucket_size_) {
			min_nr_alloc_buckets_ = initial_alloc_bucket_size_;
		}	

		if (max_nr_buckets_ && max_nr_buckets_ < initial_alloc_bucket_size_) {
			max_nr_buckets_ = initial_alloc_bucket_size_;
		}	

		const cds_lfht_mm_type		*pmmtype = nullptr;

		if (max_nr_buckets_ > 0) {
			if (prealloc_buckets == false) {
				/*
				 * Use order as mmap mm preallocates the entire bucket memory at startup...
				 */
				pmmtype = &cds_lfht_mm_order;
			}
			else {
				pmmtype = &cds_lfht_mm_mmap;
			}	
		}	

		phtable_ = _cds_lfht_new(initial_alloc_bucket_size_, min_nr_alloc_buckets_, max_nr_buckets_, flags_, pmmtype, &GY_CONCATENATE(GY_URCU_FLAVOR, flavor), presize_thr_attr_);
		if (!phtable_) {
			GY_THROW_EXPRESSION("Failed to initialize new RCU Hash Table");
		}	
	}

	RCU_HASH_TABLE(const RCU_HASH_TABLE & other)
	{
		auto rcucopylambda = [](T *pdatanode, void *arg) -> CB_RET_E
		{
			RCU_HASH_TABLE	*phtable_ = static_cast<decltype(phtable_)>(arg);
			T		*pnewdatanode = static_cast<T *>((*NewOper)(sizeof(T)));
			
			try {
				new (pnewdatanode) T((const T &)(*pdatanode));
			}
			catch(...) {
				(*DelOper)(pnewdatanode);
				throw;
			}	

			phtable_->insert_duplicate_elem(pnewdatanode, HashGetFP(pdatanode));

			return CB_OK;
		};	

		copy_table<decltype(rcucopylambda)>(other, rcucopylambda);
	}	

	RCU_HASH_TABLE(RCU_HASH_TABLE && other) noexcept	
	{
		link_table(other);

		other.phtable_ = nullptr;
		other.approxcount_.store(0, std::memory_order_relaxed) ;
	}
		
	RCU_HASH_TABLE & operator= (const RCU_HASH_TABLE & other)	
	{
		if (this == &other) {
			return *this;
		}
			
		destroy_table();
			
		auto rcucopylambda = [](T *pdatanode, void *arg) -> CB_RET_E
		{
			RCU_HASH_TABLE		*phtable_ = static_cast<decltype(phtable_)>(arg);
			T			*pnewdatanode = static_cast<T *>((*NewOper)(sizeof(T)));
			
			try {
				new (pnewdatanode) T((const T &)(*pdatanode));
			}
			catch(...) {
				(*DelOper)(pnewdatanode);
				throw;
			}	

			phtable_->insert_duplicate_elem(pnewdatanode, HashGetFP(pdatanode));

			return CB_OK;
		};	

		copy_table<decltype(rcucopylambda)>(other, rcucopylambda);

		return *this;
	}	

	RCU_HASH_TABLE & operator= (RCU_HASH_TABLE && other) noexcept
	{
		if (this == &other) {
			return *this;
		}
			
		destroy_table();	

		link_table(other);

		other.phtable_ = nullptr;
		other.approxcount_.store(0, std::memory_order_relaxed);

		return *this;
	}		

	~RCU_HASH_TABLE() noexcept
	{
		destroy_table();	
	}	
	
	/*
	 * Can be used to copy the Hash table with optional filters. Clears existing entries before copying.
	 * The FCB can be used to filter out entries not needed. e.g. :
	 * 		
	 * 		auto rcucopylambda = [minport](GY_TEST_ELEM_TYPE *pdatanode, void *arg) -> CB_RET_E
			{
				GY_TEST_HASH_TABLE	*phtable = static_cast<decltype(phtable)>(arg);
				
				// Copy only entries with port >= minport
				if (pdatanode->get_data()->port < minport) {
					return CB_OK;
				}

				GY_TEST_ELEM_TYPE	*pnewdatanode = new GY_TEST_ELEM_TYPE(*pdatanode);

				phtable->insert_duplicate_elem(pnewdatanode, pdatanode->rcu_get_hash(pdatanode));
				return CB_OK;
			};	

			dsttbl.copy_table<decltype(rcucopylambda)>(srctbl, rcucopylambda);
	 *
	 */ 		
	template <typename FCB>
	void copy_table(const RCU_HASH_TABLE & other, FCB & copy)
	{
		destroy_table();

		dealloc_attr_on_destroy_ 	= false;
		initial_alloc_bucket_size_ 	= other.initial_alloc_bucket_size_;
		min_nr_alloc_buckets_		= other.min_nr_alloc_buckets_;
		max_nr_buckets_			= other.max_nr_buckets_;
		flags_				= other.flags_;
		presize_thr_attr_		= nullptr;

		approxcount_.store(0, std::memory_order_relaxed);

		phtable_ = cds_lfht_new_flavor(initial_alloc_bucket_size_, min_nr_alloc_buckets_, max_nr_buckets_, flags_, &GY_CONCATENATE(GY_URCU_FLAVOR, flavor), presize_thr_attr_);
		if (!phtable_) {
			GY_THROW_EXCEPTION("Failed to allocate and initialize new RCU Hash Table for copying");
		}	
				
		try {
			other.walk_hash_table_const(copy, this);
		}
		catch(...) {
			destroy_table();
			throw;
		}		
	}
		
	template <typename LockType = RCU_LOCK_SLOW>
	void clear_table() noexcept
	{
		LockType		readlock;

		clear_table_internal(false /* no_gy_rcu */);
	}

	/*
	 * Clear and Destroy the table
	 */
	void destroy_table() noexcept
	{
		int			ret;
		bool			set_rcu_lock = false, is_from_call_rcu_thr;
		pthread_attr_t 		*pattr = nullptr;

		if (gy_unlikely(phtable_ == nullptr)) {
			if (dealloc_attr_on_destroy_ && presize_thr_attr_) {
				pthread_attr_destroy(presize_thr_attr_);
				presize_thr_attr_ = nullptr;
			}	

			return;	
		}
			
		is_from_call_rcu_thr = check_and_clear_table(set_rcu_lock);			
			
		/*
		 * cds_lfht_destroy() must be called from a very specific
		 * context: it needs to be called from a registered RCU reader
		 * thread. However, this thread should _not_ be within a RCU
		 * read-side critical section. Also, it should _not_ be called
		 * from a call_rcu thread.
		 *
		 * If this is called from within a call_rcu thread
		 * we offload the cds_lfht_destroy to the async func thread
		 */

		if (!is_from_call_rcu_thr && set_rcu_lock) {
			GY_CC_BARRIER();
			gy_thread_rcu().gy_rcu_thread_offline();
		}

		if (is_from_call_rcu_thr) {
			(void)rcu_send_async_destroy(phtable_);
			phtable_ = nullptr;
		}
			
		if (phtable_) {	
			ret = cds_lfht_destroy(phtable_, nullptr);
			if (ret) {
#ifdef ERRORPRINT_OFFLOAD				
				DEBUGEXECN(1, ERRORPRINT_OFFLOAD("Destroying RCU hash table failed\n"););
#else
				DEBUGEXECN(1, ERRORPRINT("Destroying RCU hash table failed\n"););
#endif				
			}
			
			phtable_ = nullptr;
		}

		if (dealloc_attr_on_destroy_ && presize_thr_attr_) {
			pthread_attr_destroy(presize_thr_attr_);
			presize_thr_attr_ = nullptr;
		}	

		if (!is_from_call_rcu_thr && set_rcu_lock) {
			GY_CC_BARRIER();
			gy_thread_rcu().gy_rcu_read_lock_online();
		}	
	}	


	/*
	 * Insert unique key : Returns true on insertion and false if the key already exists
	 * In case of false, caller is responsible for freeing memory if delete_on_error is false
	 * pdata needs to be heap allocated, key can be stack allocated as it is not stored in the table.
	 */ 
	template <typename LockType = RCU_LOCK_SLOW>
	bool insert_unique(T *pdata, const KeyType & key, uint64_t hash, bool delete_on_error = true) const noexcept(std::is_nothrow_destructible<T>::value)
	{
		/*GY_MT_COLLECT_PROFILE(100'000, "RCU Hash table unique insert");*/

		LockType		readlock;

		HashSetFP(pdata, hash);

		auto pold_cds_node = cds_lfht_add_unique(phtable_, hash, MatchFP, &key, &pdata->cds_node_);

		if (pold_cds_node != &pdata->cds_node_) {
			// Key already present

			readlock.unlock();

			if (delete_on_error) {
				Deleter()(pdata);	
			}	
			return false;
		}	

		approxcount_.fetch_add_relaxed(1, std::memory_order_relaxed, std::memory_order_relaxed);
	
		return true;
	}		

	/*
	 * Insert element, with a possible duplicate key : Note the absence of the key argument...
	 */ 
	template <typename LockType = RCU_LOCK_SLOW>
	void insert_duplicate_elem(T *pdata, uint64_t hash) const noexcept
	{
		/*GY_MT_COLLECT_PROFILE(100'000, "RCU Hash table insert duplicate");*/

		LockType		readlock;

		assert(pdata != nullptr);

		HashSetFP(pdata, hash);

		cds_lfht_add(phtable_, hash, &pdata->cds_node_);

		approxcount_.fetch_add_relaxed(1, std::memory_order_relaxed, std::memory_order_relaxed);
	}		
	
	/*
	 * Insert new element. If already existing key in the Hash Table, delete older element and replace with new.
	 * Returns false if replacement done and true if new insert. IOW, this method always succeeds (even if false is returned).
	 * pdata needs to be heap allocated, key can be stack allocated as it is not stored in the table. 
	 */ 
	template <typename LockType = RCU_LOCK_SLOW>
	bool insert_or_replace(T *pdata, const KeyType & key, uint64_t hash) const noexcept
	{
		/*GY_MT_COLLECT_PROFILE(100'000, "RCU hash table insert replace");*/

		LockType		readlock;

		HashSetFP(pdata, hash);

		auto pold_cds_node = cds_lfht_add_replace(phtable_, hash, MatchFP, &key, &pdata->cds_node_);

		if (pold_cds_node) {
			T *pdatanode = GY_CONTAINER_OF(pold_cds_node, T, cds_node_);

			// Deleting older data
			gy_thread_rcu().gy_call_rcu<T, Deleter>(&pdatanode->rcu_head_);
			return false;
		}

		approxcount_.fetch_add_relaxed(1, std::memory_order_relaxed, std::memory_order_relaxed);

		return true;	
	}		

	/*
	 * Insert unique key : Returns true on insertion and false if the key already exists in which case copy_fcb() is called.
	 *
	 * In case of false (already exists), will call copy_fcb(T *pexisting, T *pdata) which can be used for updating the
	 * older data with the new data fields or taking a reference to the older data in case of a shared_ptr. 
	 * IOW, copy_fcb will be called only if the key already exists. The copy_fcb() is called under RCU read lock.
	 * Specify delete_after_callback as true, in case the passed pdata needs to be deleted after copy_fcb() called for existing key case.
	 *
	 * pdata needs to be heap allocated, key can be stack allocated as it is not stored in the table.
	 */ 
	template <typename FCB, typename LockType = RCU_LOCK_SLOW>
	bool insert_unique(T *pdata, const KeyType & key, uint64_t hash, FCB & copy_fcb, bool delete_after_callback) const 
						noexcept(std::is_nothrow_destructible<T>::value && noexcept(copy_fcb(pdata, pdata)))
	{
		/*GY_MT_COLLECT_PROFILE(100'000, "RCU Hash table unique insert");*/

		LockType		readlock;

		HashSetFP(pdata, hash);

		auto pold_cds_node = cds_lfht_add_unique(phtable_, hash, MatchFP, &key, &pdata->cds_node_);

		if (pold_cds_node != &pdata->cds_node_) {
			// Key already present

			T 		*polddata = GY_CONTAINER_OF(pold_cds_node, T, cds_node_);
			T		*pdata_param = pdata;

			copy_fcb(polddata, pdata);

			readlock.unlock();

			if (delete_after_callback) {
				Deleter()(pdata_param);	
			}	
			return false;
		}	

		approxcount_.fetch_add_relaxed(1, std::memory_order_relaxed, std::memory_order_relaxed);
	
		return true;
	}		


	/*
	 * Walk through each element of the Hash Table. 
	 *
	 * Users need to define the following lambda which returns a CB_RET_E.
	 * The lambda should return CB_OK in normal case, CB_DELETE_ELEM to delete the element as well,
	 * CB_DELETE_BREAK to delete and break the walk and CB_BREAK_LOOP to break the walk.
	 *
	 * The Lambda is run under rcu read lock
	 * Lambda must be of type CB_RET_E (*prcu_hash_walker_cb)(T *pdatanode, void *arg);
	 *
	 * Example :	auto glambda = [&](ELEM_TYPE *pdatanode, void *arg) -> CB_RET_E
			{
				char		buf[256];
				auto		psock = pdatanode->get_data();

				int 		ret = psock->do_something();

				if (ret < 0) {
					// Terminate loop
					return CB_BREAK_LOOP;
				}	
				else if (ret > 0) {
					// We want to delete this elem and continue
					return CB_DELETE_ELEM; 
				}	
				
				// No delete here and continue
				return CB_OK;
			};	
	 * 
	 * Returns number of elements walked in the table
	 */ 

	template <typename FCB, typename LockType = RCU_LOCK_SLOW>
	size_t walk_hash_table(FCB & walk, void *arg = nullptr) const noexcept(noexcept(walk(nullptr, arg)))
	{
		size_t				niters = 0;
		struct cds_lfht_iter 		iter;
		T				*pdatanode;
		struct cds_lfht_node 		*pht_node;
		int				ret;
		CB_RET_E			cbret;

		LockType			readlock;
		RCU_SET_WALK			setwalk;
		
		cds_lfht_for_each_entry(phtable_, &iter, pdatanode, cds_node_) {

			++niters;

			cbret = walk(pdatanode, arg);

			if (cbret == CB_BREAK_LOOP) {
				break;
			}	
			else if (cbret == CB_DELETE_ELEM || cbret == CB_DELETE_BREAK) {

				pht_node = cds_lfht_iter_get_node(&iter);
				delete_rcu_locked(pht_node);

				if (cbret == CB_DELETE_BREAK) {
					break;
				}	
			}	
		}
		
		return niters;	
	}	

	
	/*
	 * Const version of walk_hash_table explained above. The walk callback should not return CB_DELETE_ELEM or CB_DELETE_BREAK.
	 */ 
	template <typename FCB, typename LockType = RCU_LOCK_SLOW>
	size_t walk_hash_table_const(FCB & walk, void *arg = nullptr) const noexcept(noexcept(walk(nullptr, arg)))
	{
		size_t				niters = 0;
		struct cds_lfht_iter 		iter;
		T				*pdatanode;
		struct cds_lfht_node 		*pht_node;
		int				ret;
		CB_RET_E			cbret;

		LockType			readlock;
		RCU_SET_WALK			setwalk;

		cds_lfht_for_each_entry(phtable_, &iter, pdatanode, cds_node_) {

			++niters;

			cbret = walk(pdatanode, arg);

			assert(cbret != CB_DELETE_ELEM && cbret != CB_DELETE_BREAK);

			if (cbret == CB_BREAK_LOOP) {
				break;
			}	
		}
		
		return niters;	
	}	

	/*
	 * Lookup with optional deletion of single element within Hash table.
	 * On successful lookup, handle_elem() callback is called and returns true. On failure returns false
	 * 
	 * Users need to define the FCB handle_elem(T *pdatanode, void *arg1, void *arg2) callback which returns 
	 * CB_OK in normal case or CB_DELETE_ELEM to delete the element. 
	 * handle_elem is called within rcu read lock context. Please avoid blocking a long time in the FCB. 
	 * arg1 and arg2 are extra arguments to be passed to handle_elem if needed.
	 *
	 * pcbmatch template param :
	 * In case the key is not available but the hash is available or lookup is needed on a separate field, users can specify a 
	 * pcbmatch function pointer to manually match each elem for that hash number instead of using the key (which can be default constructed)... 
	 * IOW, pcbmatch(struct cds_lfht_node *pht_node, const void *pkey) will be called for the elems matching with hash
	 * and then pcbmatch can select the appropriate elem. 
	 * For a custom pcbmatch, users can pass any object as key even if not of type KeyType (using reinterpret_cast) and later
	 * in the pcbmatch revert &key to appropriate type if needed as the key is not dereferenced directly and can be used only in the pcbmatch if needed.
	 */ 
	template <typename FCB, typename LockType = RCU_LOCK_SLOW, RCU_MATCH_CB pcbmatch = MatchFP>
	bool lookup_single_elem(const KeyType & key, uint64_t hash, FCB & handle_elem, void *arg1 = nullptr, void *arg2 = nullptr) const noexcept(noexcept(handle_elem(nullptr, arg1, arg2)))
	{
		struct cds_lfht_iter 		iter;
		struct cds_lfht_node 		*pht_node;
		T 				*pdatanode;
		CB_RET_E			cbret;
		LockType			readlock;

		cds_lfht_lookup(phtable_, hash, pcbmatch, &key, &iter);
		pht_node = cds_lfht_iter_get_node(&iter);

		if (!pht_node) {
			return false;
		}
			
		pdatanode = GY_CONTAINER_OF(pht_node, T, cds_node_);

		cbret = handle_elem(pdatanode, arg1, arg2);

		if (cbret == CB_DELETE_ELEM || cbret == CB_DELETE_BREAK) {
			delete_rcu_locked(pht_node);
		}	

		return true;	
	}		

	/*
	 * Lookup single element within Hash table and copies the data element to output (Copy assignable elem is needed).
	 * On success returns true
	 * See comment above for pcbmatch
	 */ 
	template <typename LockType = RCU_LOCK_SLOW, RCU_MATCH_CB pcbmatch = MatchFP, typename F = T, std::enable_if_t<std::is_copy_assignable<F>::value, int> = 0>
	bool lookup_single_elem(const KeyType  & key, uint64_t hash, T & output) const noexcept(std::is_nothrow_copy_assignable<T>::value)
	{
		struct cds_lfht_iter 		iter;
		struct cds_lfht_node 		*pht_node;
		T 				*pdatanode;
		LockType			readlock;

		cds_lfht_lookup(phtable_, hash, pcbmatch, &key, &iter);

		pht_node = cds_lfht_iter_get_node(&iter);

		if (!pht_node) {
			return false;
		}
			
		pdatanode = GY_CONTAINER_OF(pht_node, T, cds_node_);

		output = *pdatanode;

		return true;	
	}		

	/*
	 * Lookup whether a single element within Hash table exists or not. Works for duplicate elements as well. 
	 * On success returns true
	 * See comment above for pcbmatch
	 */ 
	template <typename LockType = RCU_LOCK_SLOW, RCU_MATCH_CB pcbmatch = MatchFP>
	bool lookup_single_elem(const KeyType & key, uint64_t hash) const noexcept
	{
		struct cds_lfht_iter 		iter;
		struct cds_lfht_node 		*pht_node;
		LockType			readlock;

		cds_lfht_lookup(phtable_, hash, pcbmatch, &key, &iter);

		pht_node = cds_lfht_iter_get_node(&iter);

		return !!pht_node;
	}		

	/* 
	 * Lookup whether a single element when already under an RCU read Lock. Works for duplicate elements as well. 
	 * Will return T * on success or nullptr on error.
	 *
	 * NOTE : The returned T * must only be used whilst under the same RCU read lock.
	 *
	 * See comment above for pcbmatch
	 */
	template <RCU_MATCH_CB pcbmatch = MatchFP>
	T * lookup_single_elem_locked(const KeyType & key, uint64_t hash) const noexcept
	{
		struct cds_lfht_iter 		iter;
		struct cds_lfht_node 		*pht_node;
		T 				*pdatanode;

		assert(true == gy_thread_rcu().is_rcu_in_read_lock());
		
		cds_lfht_lookup(phtable_, hash, pcbmatch, &key, &iter);

		pht_node = cds_lfht_iter_get_node(&iter);
		if (!pht_node) {
			return nullptr;
		}
			
		pdatanode = GY_CONTAINER_OF(pht_node, T, cds_node_);

		return pdatanode;	
	}		


	/*
	 * Scan multiple duplicate elements with optional deletion of multiple duplicates (same Hash and same Key) within Hash table.
	 * On success handle_elem() callback is called for each duplicate element and finally returns number of elements seen
	 * On failure returns 0
	 *
	 * Users need to define the lambda FCB which returns CB_OK in normal case, CB_BREAK_LOOP to break the loop and return or 
	 * CB_DELETE_ELEM to delete the element as well.
	 *
	 * handle_elem is called within rcu read lock. 
	 *
	 * See comment above for pcbmatch
	 *
	 */ 
	template <typename FCB, typename LockType = RCU_LOCK_SLOW, RCU_MATCH_CB pcbmatch = MatchFP>
	size_t lookup_duplicate_elems(const KeyType & key, uint64_t hash, FCB & handle_elem, void *arg1 = nullptr, void *arg2 = nullptr) const noexcept(noexcept(handle_elem(nullptr, arg1, arg2)))
	{
		struct cds_lfht_iter 		iter;
		struct cds_lfht_node 		*pht_node;
		T 				*pdatanode;
		size_t				nelems = 0;
		CB_RET_E			cbret;
		auto				pkey = &key;

		LockType			readlock;
		RCU_SET_WALK			setwalk;

		cds_lfht_for_each_entry_duplicate(phtable_, hash, pcbmatch, pkey, &iter, pdatanode, cds_node_) {
			nelems++;

			cbret = handle_elem(pdatanode, arg1, arg2);

			if (cbret == CB_BREAK_LOOP) {
				break;
			}	
			else if (cbret == CB_DELETE_ELEM || cbret == CB_DELETE_BREAK) {

				pht_node = cds_lfht_iter_get_node(&iter);
				delete_rcu_locked(pht_node);

				if (cbret == CB_BREAK_LOOP) {
					break;
				}	
			}	
		}

		return nelems;	
	}		

	/*
	 * Count number of single/duplicate elems with Key as per key and Hash as per hash. Is an O(N Duplicates) operation
	 * Specify break_after_nelems if you want to check min number of elems
	 */
	template <typename LockType = RCU_LOCK_SLOW, RCU_MATCH_CB pcbmatch = MatchFP>
	size_t count_duplicate_elems(const KeyType & key, uint64_t hash, uint32_t break_after_nelems = ~0u - 1) const noexcept
	{
		struct cds_lfht_iter 		iter;
		T 				*pdatanode;
		size_t				nelems = 0;
		auto				pkey = &key;

		LockType			readlock;

		cds_lfht_for_each_entry_duplicate(phtable_, hash, pcbmatch, pkey, &iter, pdatanode, cds_node_) {
			nelems++;

			if (nelems >= break_after_nelems) {
				break;
			}	
		}

		return nelems;	
	}		

	/*
	 * Delete single element within Hash table after copying to copyelem.
	 * On success with find and delete returns true
	 *
	 * The copy assignment operator is invoked to copy the datanode to pcopyelem before initiating destruction of the element
	 *
	 * Currently, only call_rcu based deferred destruction is allowed.
	 */ 
	template <typename LockType = RCU_LOCK_SLOW, typename F = T, std::enable_if_t<std::is_copy_assignable<F>::value, int> = 0>
	bool delete_single_elem_and_copy(const KeyType & key, uint64_t hash, T & copyelem) const noexcept(std::is_nothrow_copy_assignable<T>::value)
	{
		int				ret;
		struct cds_lfht_iter 		iter;
		struct cds_lfht_node 		*pht_node;
		T 				*pdatanode = nullptr;

		LockType			readlock;

		cds_lfht_lookup(phtable_, hash, MatchFP, &key, &iter);
		pht_node = cds_lfht_iter_get_node(&iter);

		if (!pht_node) {
			return false;
		}
			
		ret = delete_rcu_locked<T>(pht_node, copyelem);

		return !ret;
	}		
	
	/*
	 * Delete single element within Hash table.
	 * On success with find and delete returns true
	 *
	 * Currently, only call_rcu based deferred destruction is allowed.
	 */ 
	template <typename LockType = RCU_LOCK_SLOW>
	bool delete_single_elem(const KeyType & key, uint64_t hash) const noexcept
	{
		/*GY_MT_COLLECT_PROFILE(100'000, "RCU Hash Table delete");*/

		int				ret;
		struct cds_lfht_iter 		iter;
		struct cds_lfht_node 		*pht_node;
		T 				*pdatanode = nullptr;

		LockType			readlock;

		cds_lfht_lookup(phtable_, hash, MatchFP, &key, &iter);
		pht_node = cds_lfht_iter_get_node(&iter);

		if (!pht_node) {
			return false;
		}
			
		ret = delete_rcu_locked(pht_node);

		return !ret;
	}		


	/*
	 * Delete multiple duplicate elements within Hash table.
	 * On success with find and delete, returns count of elements deleted
	 *
	 * Currently, only call_rcu based deferred destruction is allowed.
	 */ 
	template <typename LockType = RCU_LOCK_SLOW>
	size_t delete_duplicate_elems(const KeyType & key, uint64_t hash) const noexcept
	{
		/*GY_MT_COLLECT_PROFILE(100'000, "RCU Hash Table delete multi duplicate");*/

		int				ret;
		struct cds_lfht_iter 		iter;
		struct cds_lfht_node 		*pht_node;
		T 				*pdatanode;
		size_t				nelems = 0;
		auto				pkey = &key;

		LockType			readlock;
		RCU_SET_WALK			setwalk;

		cds_lfht_for_each_entry_duplicate(phtable_, hash, MatchFP, pkey, &iter, pdatanode, cds_node_) {

			pht_node = cds_lfht_iter_get_node(&iter);

			ret = cds_lfht_del(phtable_, pht_node);
			if (!ret) {
				nelems++;
				gy_thread_rcu().gy_call_rcu<T, Deleter>(&pdatanode->rcu_head_);
			}
		}

		approxcount_.fetch_sub_relaxed_0(nelems, std::memory_order_relaxed, std::memory_order_relaxed);
		
		return nelems;	
	}		

	/*
	 * Delete single element within Hash table of already RCU Locked element.
	 * 
	 * Use Case : If the T * is cached say for example while walking the table and then to be deleted later on in the walk.
	 *
	 * Users need to be careful using this call to avoid "use after free" cases in case the element was previously
	 * deleted and recycled after grace period...
	 *
	 * Returns true if deleted successfully and false if already deleted (possibly by another concurrent delete.)
	 */ 
	bool delete_elem_locked(T *pdatanode) const noexcept
	{
		int			ret;

		assert(true == gy_thread_rcu().is_rcu_in_read_lock());
		
		ret = delete_rcu_locked(&pdatanode->cds_node_);

		return !ret;
	}		

	/*
	 * Replace existing element with same hash and which was previously looked up within the same RCU Lock
	 * Returns true if replacement successful. 
	 *
	 * If success and delete_old_on_succes false, the polddata must not be freed or reused till an RCU grace period is over...
	 *
	 * If false is returned (failure to replace), the pnewdata is not deleted...
	 *
	 * pnewdata needs to be heap allocated and must have same hash as was used for polddata and same key match
	 */ 
	bool replace_elem_locked(T *polddata, const KeyType & key, uint64_t hash, T *pnewdata, bool delete_old_on_success) const noexcept
	{
		int			ret;

		assert(true == gy_thread_rcu().is_rcu_in_read_lock());

		assert(polddata && pnewdata);

		ret = cds_lfht_replace(phtable_, &polddata->cds_node_, hash, MatchFP, &key, &pnewdata->cds_node_);

		if (!ret) {
			if (delete_old_on_success) {
				gy_thread_rcu().gy_call_rcu<T, Deleter>(&polddata->rcu_head_);
			}	
			
			return true;
		}

		return false;	
	}		


	/*
	 * Returns the current first element in the table or nullptr if empty. To be called under an RCU read lock context.
	 */
	T * get_first_elem_locked() const noexcept
	{
		struct cds_lfht_iter 		iter;
		struct cds_lfht_node 		*pht_node;
		T 				*pdatanode;

		assert(true == gy_thread_rcu().is_rcu_in_read_lock());

		cds_lfht_first(phtable_, &iter);
		pht_node = cds_lfht_iter_get_node(&iter);

		if (pht_node) {
			pdatanode = GY_CONTAINER_OF(pht_node, T, cds_node_);
			
			return pdatanode;	
		}
		
		return nullptr;
	}	

	/*
	 * Check if the elem previously looked up within the same RCU read lock has now been concurrently deleted
	 * from table. The elem destructor will not have been called since we are already under RCU lock.
	 */
	bool is_elem_deleted_locked(T *pdatanode) const noexcept
	{
		int			ret;

		assert(true == gy_thread_rcu().is_rcu_in_read_lock());
		
		ret = cds_lfht_is_node_deleted(&pdatanode->cds_node_);

		return !!ret;
	}		

	/*
	 * NOTE : Default LockType is RCU_LOCK_FAST
	 */
	template <typename LockType = RCU_LOCK_FAST>
	bool is_empty() const noexcept
	{
		struct cds_lfht_iter 		iter;
		struct cds_lfht_node 		*pht_node;

		LockType			readlock;

		cds_lfht_first(phtable_, &iter);
		pht_node = cds_lfht_iter_get_node(&iter);

		return !pht_node;
	}	
		
	/*
	 * Returns number of elements in the Hash Table. 
	 * The returned size can be different from actual if concurrent insert/delete operations are active.
	 *
	 * Not O(n) but is a slow operation...
	 */ 	
	template <typename LockType = RCU_LOCK_SLOW>
	size_t count_slow() const noexcept
	{
		size_t			acount = 0;
		long			split_count_before = 0, split_count_after = 0;
		LockType		readlock;

		cds_lfht_count_nodes(phtable_, &split_count_before, &acount, &split_count_after);

		approxcount_.store(acount, std::memory_order_relaxed);

		return acount;
	}
			
	/*
	 * Returns approx count of last seen number of elements.
	 *
	 * Does not use an RCU Read lock
	 */ 	
	size_t approx_count_fast() const noexcept
	{
		return approxcount_.load(std::memory_order_relaxed);
	}	

	/*
	 * Returns whether number of elements in the Hash Table >= nelems 
	 */ 	
	template <typename LockType = RCU_LOCK_SLOW>
	bool has_at_least(size_t nelems) const noexcept
	{
		if (nelems == 0) return true;

		if (nelems > 8) {
			size_t			approx = approxcount_.load(std::memory_order_relaxed);

			if ((nelems > (approx >> 1)) || (approx < 512)) {
				return (count_slow<LockType>() >= nelems);
			}	
		}

		size_t				niters = 0;
		struct cds_lfht_iter 		iter;
		T				*pdatanode;

		LockType			readlock;
		RCU_SET_WALK			setwalk;

		cds_lfht_for_each_entry(phtable_, &iter, pdatanode, cds_node_) {

			if (++niters >= nelems) {
				return true;	
			}
		}
		
		return false;	
	}	

	/*
	 * Resize the Hash Table. If auto_decrement is false within the constructor, users can call this
	 * to manually resize the Hash buckets. MUST NOT be called from within an RCU read lock as 
	 * synchronize_rcu() may be called. Note this call may block...
	 */
	void resize_table(size_t newsize) const noexcept
	{
		ensure_rcu_registered();

		assert(false == gy_thread_rcu().is_rcu_in_read_lock());

		cds_lfht_resize(phtable_, newsize);
	}	

#if 0
	/*
	 * phtable_ structure is not exposed by urcu interface include files...
	 */
	size_t bucket_count() const noexcept
	{
		return rcu_dereference(phtable_->size);
	}
#endif	

	auto key_equal_cb() const noexcept
	{
		return MatchFP;
	}

	struct cds_lfht * get_table() const noexcept
	{
		return phtable_;
	}	

protected :
	
	void link_table(const RCU_HASH_TABLE & other) noexcept
	{
		dealloc_attr_on_destroy_ 	= false;
		initial_alloc_bucket_size_ 	= other.initial_alloc_bucket_size_;
		min_nr_alloc_buckets_		= other.min_nr_alloc_buckets_;
		max_nr_buckets_			= other.max_nr_buckets_;
		flags_				= other.flags_;
		presize_thr_attr_		= nullptr;

		phtable_ 			= other.phtable_;		// Shallow copy

		approxcount_.store(other.approxcount_.load(std::memory_order_relaxed), std::memory_order_relaxed);
	}

	int delete_rcu_locked(struct cds_lfht_node *pht_node) const noexcept
	{
		int			ret;
		T 			*pdatanode = nullptr;
			
		ret = cds_lfht_del(phtable_, pht_node);
		if (!ret) {
			approxcount_.fetch_sub_relaxed_0(1, std::memory_order_relaxed, std::memory_order_relaxed);

			pdatanode = GY_CONTAINER_OF(pht_node, T, cds_node_);

			gy_thread_rcu().gy_call_rcu<T, Deleter>(&pdatanode->rcu_head_);
		}

		return ret;
	}	

	template <typename F = T, std::enable_if_t<std::is_copy_assignable<F>::value, int> = 0>
	int delete_rcu_locked(struct cds_lfht_node *pht_node, T & copyelem) const noexcept(std::is_nothrow_copy_assignable<T>::value)
	{
		int			ret;
		T 			*pdatanode = nullptr;
			
		ret = cds_lfht_del(phtable_, pht_node);
		if (!ret) {
			approxcount_.fetch_sub_relaxed_0(1, std::memory_order_relaxed, std::memory_order_relaxed);

			pdatanode = GY_CONTAINER_OF(pht_node, T, cds_node_);

			copyelem = *pdatanode;
				
			gy_thread_rcu().gy_call_rcu<T, Deleter>(&pdatanode->rcu_head_);
		}

		return ret;
	}	

	[[gnu::noinline]] 
	bool check_and_clear_table(bool & set_rcu_lock) noexcept
	{
		auto			pdata = GY_CONCATENATE(GY_URCU_FLAVOR, get_default_call_rcu_data)();
		auto 			pdatathr = GY_CONCATENATE(GY_URCU_FLAVOR, get_thread_call_rcu_data)();

		if ((pdata && (pthread_equal(pthread_self(), GY_CONCATENATE(GY_URCU_FLAVOR, get_call_rcu_thread)(pdata)))) || 
				(pdatathr && (pthread_equal(pthread_self(), GY_CONCATENATE(GY_URCU_FLAVOR, get_call_rcu_thread)(pdatathr))))) {

			/*
			 * Called from within a call_rcu thread. Must not invoke rcu read locks
			 */ 
			clear_table_internal(true /* no_gy_rcu */);
			
			set_rcu_lock = false;
			return true;
		}
			
		clear_table();
		set_rcu_lock = gy_thread_rcu().is_rcu_in_read_lock();

		return false;
	}

	/*
	 * Must be RCU Locked unless no_gy_rcu == true which is the case when called from the call_rcu thread directly...
	 */
	void clear_table_internal(bool no_gy_rcu) noexcept
	{
		int				ret;
		struct cds_lfht_iter 		iter;
		struct cds_lfht_node 		*pht_node;
		T 				*pdatanode;
		bool				reset_walk = false;
			
		if (no_gy_rcu == false) {
			GY_CC_BARRIER();

			if (gy_thread_rcu().is_walk_running_ == false) {
				gy_thread_rcu().is_walk_running_ = true;
				reset_walk = true;
			}	
		}	

		GY_SCOPE_EXIT {
			if (no_gy_rcu == false) {
				GY_CC_BARRIER();

				if (reset_walk) {
					gy_thread_rcu().is_walk_running_ = false;
				}	
			}	
		};	

		cds_lfht_for_each_entry(phtable_, &iter, pdatanode, cds_node_) {

			pht_node = cds_lfht_iter_get_node(&iter);

			ret = cds_lfht_del(phtable_, pht_node);
			if (!ret) {
				if (no_gy_rcu == false) {
					GY_CC_BARRIER();
					gy_thread_rcu().gy_call_rcu<T, Deleter>(&pdatanode->rcu_head_);
				}
				else {
					GY_CONCATENATE(GY_URCU_FLAVOR, call_rcu)(&pdatanode->rcu_head_, gy_call_rcu_free_node<T, Deleter>);		
				}		
			}
		}

		approxcount_.store(0, std::memory_order_relaxed);
	}
};
	
} // namespace gyeeta
