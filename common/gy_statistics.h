
/*
 * Provides a Bounded Priority Queue, a fast Histogram implementation and a Windowed Time Histogram based on a modified folly::TimeseriesSlabHistogram
 */ 
#pragma 		once

#include		"gy_common_inc.h"
#include		"gy_rcu_inc.h"
#include		"gy_print_offload.h"

#include		<chrono>
#include 		"TimeseriesSlabHistogram.h"
#include 		"TimeseriesSlabHistogram-defs.h"

namespace gyeeta {

/*
 * Thread-safe (using an inline mutex) Bounded priority queue with iteration support. Use for storing Top N OR Least N items.
 * If thread safety not needed specify NULL_MUTEX as the ScopeLock. 
 *
 * To use as a Top N Priority Queue, specify a comparator which returns if 1st arg > 2nd i.e. return lhs > rhs 
 * For a Least N Priority Queue, specify a comparator which returns if 2nd arg > 1st i.e. return rhs > lhs
 *
 * Recommended that a valid noexcept move constructor and assignment methods be defined for T for better efficiency.
 */ 
template <typename T, typename Comp = std::greater<T>, typename ScopeLock = SCOPE_GY_MUTEX, typename VectorType = std::vector<T>>
class BOUNDED_PRIO_QUEUE
{
public :	
	VectorType			vecq_;
	uint32_t			maxsz_			{0};
	bool				reserve_		{true};
	Comp				comp_;
	mutable GY_MUTEX		mutex_;

	static_assert(noexcept(comp_(std::declval<T>(), std::declval<T>())), "Comparator operator () needs to be noexcept");

	BOUNDED_PRIO_QUEUE(size_t maxsz, bool reserve = true) : maxsz_(maxsz), reserve_(reserve)
	{
		if (reserve == true) {
			vecq_.reserve(maxsz_);
		}	
	}	
		
	BOUNDED_PRIO_QUEUE(size_t maxsz, const typename VectorType::allocator_type & alloc, bool reserve = true) 
		: vecq_(alloc), maxsz_(maxsz)
	{
		if (reserve == true) {
			vecq_.reserve(maxsz_);
		}	
	}	

	BOUNDED_PRIO_QUEUE(const BOUNDED_PRIO_QUEUE &other)
		: maxsz_(other.maxsz_), reserve_(other.reserve_), comp_(other.comp_)
	{
		ScopeLock		lock(&other.mutex_);

		vecq_			= other.vecq_;
	}	
			
	BOUNDED_PRIO_QUEUE(BOUNDED_PRIO_QUEUE && other) noexcept(std::is_nothrow_move_constructible<T>::value && std::is_nothrow_move_constructible<VectorType>::value)
		: vecq_(std::move(other.vecq_)), maxsz_(other.maxsz_), reserve_(other.reserve_), comp_(std::move(other.comp_))
	{}	
			
	BOUNDED_PRIO_QUEUE & operator= (const BOUNDED_PRIO_QUEUE &other)
	{
		if (this != &other) {
			ScopeLock		lock(&other.mutex_);
			 
			vecq_ 			= other.vecq_;
			maxsz_ 			= other.maxsz_;
			reserve_		= other.reserve_;
			comp_ 			= other.comp_;
		}
		return *this;
	}	
			
	BOUNDED_PRIO_QUEUE & operator= (BOUNDED_PRIO_QUEUE && other) noexcept(std::is_nothrow_move_assignable<T>::value && std::is_nothrow_move_assignable<VectorType>::value)
	{
		if (this != &other) {
			vecq_ 		= std::move(other.vecq_);
			maxsz_ 		= other.maxsz_;
			reserve_	= other.reserve_;
			comp_ 		= std::move(other.comp_);
		}
		return *this;
	}

	~BOUNDED_PRIO_QUEUE() noexcept		= default;

	void set_comparator(Comp && compin)
	{
		comp_ = std::move(compin);
	}	

	Comp & get_comparator() noexcept
	{
		return comp_;
	}	

	// Returns true if element is inserted
	bool push(T && data)
	{
		ScopeLock		lock(&mutex_);
		
		return push_locked(std::forward<T>(data));
	}	

	// Returns true if element is inserted
	bool push(T & data)
	{
		ScopeLock		lock(&mutex_);
		
		return push_locked(std::forward<T>(data));
	}	
	
	// Returns true if element is inserted
	template <typename Compfcb, typename... Args>
	bool try_emplace(Compfcb & comp, Args && ...args)
	{
		ScopeLock		lock(&mutex_);

		return try_emplace_locked(comp, std::forward<Args>(args)...);
	}

	/*
	 * Returns true if new element is emplaced. Calls Compfcb for comparison and after comparison calls Retfcb with bool arg. 
	 * Can be used to do some additonal work under mutex lock on success/failure
	 e.g.
		// Called under mutex lock
		const auto retcb = [this, currtsec](bool elem_added) noexcept
		{
			if (elem_added) {
				tlastq_.store(currtsec, std::memory_order_relaxed);
			}	
		};	

		// Called under mutex lock
		const auto compcb = [currtsec](const NOTIFY_MSG_ONE & rhs) noexcept
		{
			return currtsec > rhs.tmsg_;
		};	

		notifyq_.try_emplace_check(retcb, compcb, ntype, pmsg, msglen, currtsec, machid);
	 */
	template <typename Retfcb, typename Compfcb, typename... Args>
	bool try_emplace_check(Retfcb & retcb, Compfcb & comp, Args && ...args)
	{
		bool			bret;
		ScopeLock		lock(&mutex_);

		bret = try_emplace_locked(comp, std::forward<Args>(args)...);

		retcb(bret);

		return bret;
	}

	void pop()
	{
		ScopeLock		lock(&mutex_);

		pop_locked();
	}	

	/*
	 * Iterate through the priority queue with optional sorting.
	 *
	 * FCB Lambda type : [Captures] (T & datanode, void *arg1, void *arg2) -> CB_RET_E 
	 * The FCB callback is under scope lock. 
	 *
	 * Specify return code from fcb as CB_BREAK_LOOP to break the iteration.
	 *
	 * By default the items will not be sorted. Only the top element is the minimum one for Top N and 
	 * maximium one for Least N. If sort_queue is specified, then an extra sort and make_heap is needed
	 * so use only if needed. 
	 * 
	 * If sort_queue == true && heap_on_return is false, then on return the queue is left in a sorted 
	 * state and is not a valid Heap. In that case, users need to manually call this->make_heap() in case new elements
	 * need to be pushed subsequently as the queue is not a Heap currently.
	 * 
	 */ 	
	template <typename FCB, typename ScopeLockWalk = ScopeLock>
	size_t walk_queue(FCB &fcb, void *arg1 = nullptr, void *arg2 = nullptr, bool sort_queue = false, bool heap_on_return = true)
	{
		size_t			nret = 0;

		ScopeLockWalk		lock(&mutex_);

		if (gy_unlikely(empty())) {
			return 0;
		}	
			
		if (sort_queue == true) {
			std::sort_heap(vecq_.begin(), vecq_.end(), comp_);
		}

		GY_SCOPE_EXIT {
			if ((sort_queue == true) && (heap_on_return == true)) {
				try {
					std::make_heap(vecq_.begin(), vecq_.end(), comp_);
				}
				catch(...) {
				}
			}	
		};	
			
		for (auto && elem : vecq_) {
			CB_RET_E	ret;

			nret++;

			ret = fcb(elem, arg1, arg2);
			if (ret == CB_BREAK_LOOP) {
				break;
			}	
		}	

		return nret;
	}	

	/*
	 * const walk version. See comment above. No sorting will be enabled.
	 * In case the T is not a pointer type and the underlying vector is already allocated
	 * it is safe to walk without locking (if set_max_size() or clear() will not be called), in which case the ScopeLockConst can be passed as 
	 * NULL_MUTEX
	 *
	 * Specify return code from fcb as CB_BREAK_LOOP to break the iteration.
	 */ 
	template <typename FCB, typename ScopeLockConst = ScopeLock>
	size_t walk_queue_const(FCB &fcb, void *arg1 = nullptr, void *arg2 = nullptr) const
	{
		size_t			nret = 0;

		ScopeLockConst		lock(&mutex_);

		if (gy_unlikely(empty())) {
			return 0;
		}	
			
		for (const auto & elem : vecq_) {
			CB_RET_E	ret;

			nret++;

			ret = fcb(elem, arg1, arg2);
			if (ret == CB_BREAK_LOOP) {
				break;
			}	
		}	

		return nret;
	}	

	/*
	 * Deletes priority queue elements based on the Compfcb and returns num elems deleted. 
	 * Specify heap_on_return as true to make the prio queue a heap again after deletion.
	 */
	template <typename Compfcb, typename ScopeLockWalk = ScopeLock>
	size_t remove_elems(Compfcb & comp, bool heap_on_return = true)
	{
		size_t			ndel = 0;

		ScopeLockWalk		lock(&mutex_);

		if (gy_unlikely(empty())) {
			return 0;
		}	
			
		auto 		it = std::remove_if(vecq_.begin(), vecq_.end(), comp);

		ndel = std::distance(it, vecq_.end());

		vecq_.erase(it, vecq_.end());
		
		if (heap_on_return == true) {
			make_heap_locked();
		}	

		return ndel;
	}	

	/*
	 * Users can call make_heap() after sorting the queue in order to push new elements.
	 */
	void make_heap() noexcept
	{
		ScopeLock		lock(&mutex_);
		
		make_heap_locked();
	}

	void sort_heap()
	{
		ScopeLock		lock(&mutex_);

		sort_heap_locked();
	}

	void clear()
	{
		ScopeLock		lock(&mutex_);

		clear_locked();
	}	

	bool empty() const noexcept
	{
		return vecq_.empty();
	}	

	// Not thread-safe 
	const T & top() const noexcept
	{
		return vecq_.front();
	}	

	size_t max_size() const noexcept
	{
		return maxsz_;
	}	

	size_t size() const noexcept
	{
		ScopeLock		lock(&mutex_);

		return size_locked();
	}	

	// Increase/Decease max elems
	void set_max_size(size_t new_max_sz)
	{
		ScopeLock		lock(&mutex_);
		
		if (new_max_sz == maxsz_) {
			return;
		}
		
		if (new_max_sz > maxsz_) {
			maxsz_ = new_max_sz;	
			vecq_.reserve(new_max_sz);

			return;
		}		

		for (size_t sz = vecq_.size(); (ssize_t)sz > (ssize_t)new_max_sz; sz--) {
			pop_locked();
		}	

		maxsz_ = new_max_sz;
		vecq_.shrink_to_fit();
	}	

	bool push_locked(T && data)
	{
		if (vecq_.size() < maxsz_) {
			vecq_.push_back(std::forward<T>(data));

			if (vecq_.size() > 6) {
				std::push_heap(vecq_.begin(), vecq_.end(), comp_);
			}
			else {
				std::make_heap(vecq_.begin(), vecq_.end(), comp_);
			}	
			return true;
		}	
		
		T 	& top = vecq_.front();

		if (true == comp_(data, top)) {
			std::pop_heap(vecq_.begin(), vecq_.end(), comp_);
			vecq_.pop_back();

			vecq_.push_back(std::forward<T>(data));
			std::push_heap(vecq_.begin(), vecq_.end(), comp_);

			return true;
		}

		return false;	
	}	

	template <typename Compfcb, typename... Args>
	bool try_emplace_locked(Compfcb & comp, Args && ...args)
	{
		if (vecq_.size() < maxsz_) {
			vecq_.emplace_back(std::forward<Args>(args)...);

			if (vecq_.size() > 6) {
				std::push_heap(vecq_.begin(), vecq_.end(), comp_);
			}
			else {
				std::make_heap(vecq_.begin(), vecq_.end(), comp_);
			}	
			return true;
		}	
		
		T 	& top = vecq_.front();

		if (true == comp(top)) {
			std::pop_heap(vecq_.begin(), vecq_.end(), comp_);
			vecq_.pop_back();

			vecq_.emplace_back(std::forward<Args>(args)...);
			std::push_heap(vecq_.begin(), vecq_.end(), comp_);

			return true;
		}

		return false;	

	}	

	void pop_locked()
	{
		if (gy_unlikely(empty())) {
			return;
		}	

		std::pop_heap(vecq_.begin(), vecq_.end(), comp_);
		vecq_.pop_back();
	}			

	void clear_locked()
	{
		vecq_.clear();

		if (reserve_ == true) {
			vecq_.reserve(maxsz_);
		}
	}	

	void make_heap_locked() noexcept
	{
		try {
			std::make_heap(vecq_.begin(), vecq_.end(), comp_);
		}
		catch(...) {
		}
	}

	void sort_heap_locked()
	{
		std::sort_heap(vecq_.begin(), vecq_.end(), comp_);
	}

	size_t size_locked() const noexcept
	{
		return vecq_.size();
	}	
};	

/*
 * Struct to store histogram data for serialization
 */
struct HIST_SERIAL
{
	uint64_t		count		{0};
	int64_t			sum		{0};	

	void add(int64_t data) noexcept
	{
		sum += data;
		count++;
	}	
};

/*
 * Struct to retrieve GY_HISTOGRAM percentile based data
 */
struct HIST_DATA
{
	int64_t				data_value	{0};
	int64_t				sum		{0};
	size_t				count		{0};
	float				percentile	{0};

	HIST_DATA(float pct) noexcept : percentile(pct)
	{}	

	HIST_DATA() noexcept		= default;
};

/*
 * Struct to retrieve TIME_HISTOGRAM percentile based data
 */
struct TIME_HIST_VAL
{
	int64_t				data_value	{0};
	float				percentile	{0};

	TIME_HIST_VAL() noexcept		= default;

	TIME_HIST_VAL(float pct) noexcept : percentile(pct)
	{}	
};

template <typename HashClass, typename T = int64_t>
static constexpr int64_t get_bucket_max_threshold(size_t id) noexcept 
{
	if (id == 0) {
		return HashClass::min_value - 1;
	}	
	else if (id >= HashClass::max_buckets - 1) {
		int64_t maxt = std::numeric_limits<T>::max(), lesst;

		lesst = HashClass::max_value >= INT_MAX ? LONG_MAX : (HashClass::max_value > (SHRT_MAX >> 1) ? INT_MAX : SHRT_MAX);

		return lesst < maxt ? lesst : maxt;
	}
		
	return HashClass::nthresholds[id - 1];
}

template <typename HashClass>
static constexpr size_t get_bucketid_from_threshold(int64_t threshold) noexcept 
{
	for (size_t i = 0; i < GY_ARRAY_SIZE(HashClass::nthresholds); ++i) {
		if (threshold == HashClass::nthresholds[i]) {
			return i + 1;
		}	
	}	
		
	if (threshold < HashClass::min_value) {
		return 0;
	}

	return HashClass::max_buckets - 1;
}

template <typename LevelClass>
static constexpr int get_level_from_time_offset(std::chrono::seconds time_offset) noexcept 
{
	for (size_t i = 0; i < LevelClass::ntime_levels; i++) {
		if (time_offset == LevelClass::dist_seconds[i]) {
			return (int)i;		
		}	
	}

	return -1;
}	

static constexpr size_t			GY_MAX_HISTOGRAM_BUCKETS	= 512;	
static constexpr size_t			GY_MAX_HISTOGRAM_TIME_LEVELS	= 32;	

/*
 * High performance Histogram approx. No heap allocations. 
 * Not thread safe but safe to read from multiple threads if minor discrepancies are ok.
 */ 
template <typename T, typename HashClass>
class GY_HISTOGRAM
{
public :	
	static constexpr size_t		maxbuckets_ = HashClass::get_max_buckets();

	uint64_t			end_clock_sec_;
	HIST_SERIAL			stats_[maxbuckets_]		{};
	size_t				total_count_			{0};
	T				max_val_seen_			{std::numeric_limits<T>::min()};
	uint64_t			start_clock_sec_;				
	HashClass			hash_;

	static_assert(std::is_integral<T>::value, "Integral data types allowed");

	static_assert(true == noexcept(std::declval<HashClass>()((T)0)), "Hash operator() needs to be noexcept");

	GY_HISTOGRAM(uint64_t start_clock_sec = get_sec_clock()) noexcept(std::is_nothrow_default_constructible<HashClass>::value) 
		: end_clock_sec_(start_clock_sec), start_clock_sec_(start_clock_sec)
	{}	

	GY_HISTOGRAM(const GY_HISTOGRAM &) noexcept(std::is_nothrow_copy_constructible<HashClass>::value)		= default;

	GY_HISTOGRAM(GY_HISTOGRAM &&) noexcept(std::is_nothrow_move_constructible<HashClass>::value)			= default;

	GY_HISTOGRAM & operator= (const GY_HISTOGRAM &) noexcept(std::is_nothrow_copy_assignable<HashClass>::value)	= default;

	GY_HISTOGRAM & operator= (GY_HISTOGRAM &&) noexcept(std::is_nothrow_move_assignable<HashClass>::value)		= default;
	
	HashClass get_hash_class() const noexcept
	{
		return HashClass();
	}	

	/*
	 * Add a new metric to the Histogram. 
	 *
	 * curr_clock_sec is the current time (Specify only if last addition time is needed. 
	 * If not, you can specify a constant value to avoid the overhead of a clock_gettime() vsyscall.)
	 *
	 * If the bucketid under which the new data is to be stored has been already calculated, you can specify that within bucketid.
	 *
	 * Not thread safe but OK if some discrepancies could be withstood. Returns the bucketid to which this data is stored.
	 */ 
	size_t add_data(T data, uint64_t curr_clock_sec = 0, size_t bucketid = ~0u) noexcept
	{
/* 		GY_NOMT_COLLECT_PROFILE(100000, "Histogram : Add data"); */

		size_t			bucket;
		
		if (bucketid == ~0u) {
			bucket = hash_(data);
		}
		else {
			bucket = bucketid;
		}		

		assert(bucket < maxbuckets_);

		stats_[bucket].add(data);
		total_count_++;

		if (max_val_seen_ < data) {
			max_val_seen_ = data;
		}
			
		if (curr_clock_sec) {
			end_clock_sec_ 	= curr_clock_sec;
		}	

		return bucket;
	}	

	void add_histogram(const GY_HISTOGRAM & thist) noexcept
	{
		update_from_serialized(thist.stats_, thist.total_count_, thist.max_val_seen_, thist.end_clock_sec_, thist.start_clock_sec_);
	}
		
	void clear() noexcept
	{
		std::memset(stats_, 0, sizeof(stats_));
		end_clock_sec_ 	= start_clock_sec_;
		total_count_ = 0;	
		max_val_seen_ = std::numeric_limits<T>::min();
	}	

	/*
	 * Update the histogram based based on a serialized data. (Only addition is done)
	 */ 
	void update_from_serialized(const HIST_SERIAL stats_arr[maxbuckets_], size_t total_count, T max_val, uint64_t end_clock = 0, uint64_t start_clock = ~0ul) noexcept
	{
		for (size_t i = 0; i < maxbuckets_; ++i) {
			stats_[i].count 	+= stats_arr[i].count;
			stats_[i].sum	 	+= stats_arr[i].sum;
		}

		total_count_ += total_count; 
		if (max_val_seen_ < max_val) {
			max_val_seen_ = max_val;
		}
			
		if (end_clock_sec_ > end_clock) {
			end_clock_sec_ 		= end_clock;	
		}		

		if (start_clock_sec_ < start_clock) {
			start_clock_sec_	= start_clock;
		}
	}	

	/*
	 * Get the current data in a serialable form
	 */ 
	void get_serialized(HIST_SERIAL stats_arr[maxbuckets_], size_t & total_count, T & max_val, uint64_t & end_clock, uint64_t & start_clock) const noexcept
	{
		std::memcpy(stats_arr, stats_, sizeof(stats_));

		total_count 	= total_count_;
		max_val		= max_val_seen_;
		end_clock	= end_clock_sec_;
		start_clock	= start_clock_sec_;
	}	

	void get_total_max(size_t & total_count, T & max_val) const noexcept
	{
		total_count 	= total_count_;
		max_val		= max_val_seen_;
	}
		
	size_t get_total_count() const noexcept
	{
		return total_count_;
	}

	// Not completely thread safe : Ok if some discrepancies are allowed
	T get_percentile(float percentile) const noexcept
	{
		HIST_DATA	one {percentile};
		size_t 		total_count;
		T 		max_val;

		get_percentiles(&one, 1, total_count, max_val);

		return (T)one.data_value;
	}

	/*
	 * Get the Histogram percentiles
	 *
	 * Set the list of percentiles needed within pdata array.
	 *
	 * Pass a non-null stats_arr if the underlying stats bucket data is needed.
	 *
	 * Not completely thread safe : Ok if some discrepancies are allowed
	 */ 
	void get_percentiles(HIST_DATA * pdata, size_t npercentile, size_t & total_count, T & max_val, float * pavg = nullptr, HIST_SERIAL stats_arr[maxbuckets_] = nullptr) const noexcept
	{
		/*GY_MT_COLLECT_PROFILE(1000, "Histogram : Get Statistics");*/

		assert(pdata);

		static constexpr size_t		arrsize = (maxbuckets_ <= 50 ? maxbuckets_ : 1);

		size_t				total;	
		int64_t				sum;
		HIST_SERIAL			tstatarr[arrsize];
		const HIST_SERIAL		*pstatarr;

		if (maxbuckets_ <= 50) {
			std::memcpy(tstatarr, stats_, sizeof(stats_));
			pstatarr = tstatarr;
		}	
		else {
			pstatarr = stats_;
		}	

		total_count 	= total_count_;
		max_val		= max_val_seen_;

		if (pavg) {
			int64_t			total_sum = 0, cnt;
			
			if (total_count) {
				cnt = (int64_t)total_count;
			}
			else {
				cnt = 1;
			}	
				
			for (size_t i = 0; i < maxbuckets_; ++i) {
				total_sum 	+= pstatarr[i].sum;
			}	
			
			*pavg 	= (total_sum * 1.0f)/cnt;
		}

		if (stats_arr) {
			std::memcpy(stats_arr, pstatarr, sizeof(stats_));
		}

		for (size_t n = 0; n < npercentile; ++n) {
			float			multiplier = pdata[n].percentile/100.0;
			const size_t		ncutoff = total_count * multiplier;
			size_t 			i;

			assert(pdata[n].percentile <= 100.0f && pdata[n].percentile > 0.00000f);

			total 			= 0;
			sum 			= 0;

			for (i = 0; i < maxbuckets_; ++i) {

				total 		+= pstatarr[i].count;
				sum 		+= pstatarr[i].sum;

				if (total >= ncutoff) {
					pdata[n].count		= total;
					pdata[n].data_value 	= (T)get_bucket_max_threshold<HashClass, T>(i);
					pdata[n].sum 		= sum;

					break;
				}
			}	
			
			if (i < maxbuckets_) {
				continue;
			}	
	
			if (total_count > 0) {
				pdata[n].count		= total;
				pdata[n].data_value 	= (T)get_bucket_max_threshold<HashClass, T>(maxbuckets_);
				pdata[n].sum		= sum;
			}	
			else {
				pdata[n].count		= total;
				pdata[n].data_value 	= (T)get_bucket_max_threshold<HashClass, T>(0);
				pdata[n].sum		= sum;
			}
		}
	}	

	void get_start_end_time(uint64_t & start_clock_sec, uint64_t & end_clock_sec) const noexcept
	{
		start_clock_sec 	= GY_READ_ONCE(start_clock_sec_);
		auto tend_clock_sec	= GY_READ_ONCE(end_clock_sec_);
	
		if (tend_clock_sec >= start_clock_sec) {
			end_clock_sec 	= tend_clock_sec;
		}	
		else {
			end_clock_sec	= start_clock_sec;
		}	
	}

	uint64_t get_start_time() const noexcept
	{
		return GY_READ_ONCE(start_clock_sec_);
	}	

	uint64_t get_end_time() const noexcept
	{
		return GY_READ_ONCE(end_clock_sec_);
	}	
		
	char * print_stats(const char *pstrbuf, size_t nbytes, const float * percentile_array, size_t npct, const char *metric_string = "Data", uint64_t clock_to_sec_divisor = 1) const noexcept
	{
		return print_stats({pstrbuf, nbytes}, percentile_array, npct, metric_string, clock_to_sec_divisor);
	}
		
	char * print_stats(STR_WR_BUF & strbuf, const float * percentile_array, size_t npct, const char *metric_string = "Data", uint64_t clock_to_sec_divisor = 1) const noexcept
	{
		try {
			HIST_DATA 		data[npct];
			T			max_val;
			size_t			total_count;
			float			avg_val;
			uint64_t		start_clock_sec, end_clock_sec;
			HIST_SERIAL		*pstatsarr;
			bool			is_malloc;
			uint8_t			*ptmp;
			
			SAFE_STACK_ALLOC(ptmp, sizeof(stats_), is_malloc);

			pstatsarr = reinterpret_cast<HIST_SERIAL *>(ptmp);
			if (!pstatsarr) {
				return strbuf.buffer();
			}	

			for (size_t i = 0; i < npct; ++i) {
				data[i].percentile	= percentile_array[i];
			}
				
			get_percentiles(data, npct, total_count, max_val, &avg_val, pstatsarr);
			get_start_end_time(start_clock_sec, end_clock_sec);
			
			if (clock_to_sec_divisor == 0) clock_to_sec_divisor = 1;

			strbuf.appendfmt("Histogram Statistics : Total Records %lu : Avg Records/sec %lu : Overall Average %.3f : Max Value ", 
				total_count, total_count/(end_clock_sec > start_clock_sec && end_clock_sec - start_clock_sec > clock_to_sec_divisor ? 
				(end_clock_sec - start_clock_sec)/clock_to_sec_divisor : 1), avg_val);
			strbuf.append(max_val);
			strbuf.appendconst("\n\t");

			for (size_t i = 0; i < npct; ++i) {
				strbuf.appendfmt("[ p%.5f is <= ", data[i].percentile);
				strbuf.append(data[i].data_value);
				strbuf.appendconst(" : Count ");
				strbuf.append(data[i].count);
				strbuf.appendconst(" Sum ");
				strbuf.append(data[i].sum);
				strbuf.appendconst(" ] ");
			}

			strbuf.appendconst("\n\t");

			for (size_t i = 0; i < maxbuckets_; ++i) {
				strbuf.appendfmt("[ %s <= ", metric_string);
				strbuf.append((T)get_bucket_max_threshold<HashClass, T>(i));
				strbuf.appendconst(" : Count ");
				strbuf.append(pstatsarr[i].count);
				strbuf.appendconst(" Sum ");
				strbuf.append(pstatsarr[i].sum);
				strbuf.appendconst(" ] ");
			}	
			
			strbuf.append('\n');

		}
		catch(...) {
		}	

		return strbuf.buffer();
	}	

	void print_stats_stdout(const char *metric_string = "Data", uint64_t clock_to_sec_divisor = 1) const noexcept
	{
		float			pctarr[] {25, 50, 95, 99};
		STRING_BUFFER<4096>	strbuf;

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Histogram Stats for %s : %s\n\n", 
			metric_string, print_stats(strbuf, pctarr, GY_ARRAY_SIZE(pctarr), metric_string, clock_to_sec_divisor));
	}	
};


/*
 * GY_HISTOGRAM along with a cache of the recently added data
 */ 
template <typename T, typename HashClass, uint8_t nhistory>
class GY_HISTOGRAM_DATA
{
public :
	using Histogram = GY_HISTOGRAM<T, HashClass>;

	typedef typename std::conditional<HashClass::get_max_buckets() < 256, uint8_t, uint16_t>::type 	BucketIdType;

	static_assert(HashClass::get_max_buckets() < GY_MAX_HISTOGRAM_BUCKETS);

	Histogram			histogram_;
	T				datahist_[nhistory]	{};
	BucketIdType			buckethist_[nhistory]	{};
	uint8_t				curridx_		{0};
	
	GY_HISTOGRAM_DATA(uint64_t start_clock_sec = get_sec_clock()) noexcept(std::is_nothrow_default_constructible<HashClass>::value) 
		: histogram_(start_clock_sec)
	{}	

	// Not thread-safe
	size_t add_data(T data, uint64_t curr_clock_sec = get_sec_clock(), size_t bucketid = ~0u) noexcept
	{
		BucketIdType		cid;
		uint8_t			idx = curridx_ % nhistory;
		
		curridx_++;
		if (curridx_ >= nhistory) curridx_ = 0;

		cid = static_cast<BucketIdType>(histogram_.add_data(data, curr_clock_sec, bucketid));

		datahist_[idx] 		= data;
		buckethist_[idx]	= cid;

		return cid;
	}	

	// 0th element will the latest data item
	void get_history(T (&histarr)[nhistory]) const noexcept
	{
		uint8_t			cid = curridx_;
		uint32_t 		i, n = 0;

		for (i = cid - 1; (int)i >= 0; --i, ++n) {
			histarr[n] = datahist_[i];
		}	

		for (i = nhistory - 1; (int)i >= (int)cid; --i, ++n) {
			histarr[n] = datahist_[i];
		}	
	}
	
	char * print_stats(STR_WR_BUF & strbuf, const float * percentile_array, size_t npct, const char *metric_string = "Data", uint64_t clock_to_sec_divisor = 1, bool print_hist = true) const noexcept
	{
		histogram_.print_stats(strbuf, percentile_array, npct, metric_string, clock_to_sec_divisor);
		
		if (print_hist == false) {
			return strbuf.buffer();
		}
			
		uint8_t			cid = curridx_;
		uint32_t 		i, n = 0;

		strbuf.appendfmt("\tLast %hhu %s History : [", nhistory, metric_string);

		for (i = cid - 1; (int)i >= 0; --i, ++n) {
			strbuf.append(datahist_[i]);
			strbuf.append(',');
		}	

		for (i = nhistory - 1; (int)i >= (int)cid; --i, ++n) {
			strbuf.append(datahist_[i]);
			strbuf.append(',');
		}	

		strbuf.set_last_char(']');
		strbuf.append('\n');

		return strbuf.buffer();
	}
};	

/*
 * Cache for TIME_HISTOGRAM : See comments for TIME_HISTOGRAM below
 *
 * Use as a per thread cache for TIME_HISTOGRAM for faster inserts as Mutex Locking avoided. 
 * Will flush data periodically to the actual Histogram.
 */ 
template <typename Histogram, typename HashClass>
class TIME_HIST_CACHE
{
public :	
	static constexpr size_t		maxbuckets = HashClass::get_max_buckets();

	HIST_SERIAL			cache[maxbuckets];				
	time_t				tcurrbucket;

	HashClass			hash;
	Histogram * const		phistogram;		

	const time_t			tstarttime;	

	static_assert(HashClass::get_max_buckets() < GY_MAX_HISTOGRAM_BUCKETS && HashClass::get_max_buckets() > 1);

	static_assert(true == noexcept(std::declval<HashClass>()(0)), "Hash Operator () needs to be noexcept");

	TIME_HIST_CACHE(Histogram * phist) noexcept :
		tcurrbucket(time(nullptr)), phistogram(phist), tstarttime(tcurrbucket)
	{
		assert(phistogram);

		std::memset(cache, 0, sizeof(cache));	
	}		
	
	int add_cache(int64_t data, size_t & bucket_id, time_t tnow = time(nullptr)) noexcept
	{
		size_t			bucket = hash(data);

		assert(bucket < maxbuckets);

		bucket_id = bucket;

		if (tnow != tcurrbucket) {
			// Update the actual histogram
			
			flush_to_histogram();
			tcurrbucket = tnow;
		}	

		cache[bucket].add(data);

		return 0;
	}	

	int flush_to_histogram() noexcept
	{
		int			ret;
		HIST_SERIAL 		tmpcache[64], *ptmpcache;
		bool 			is_alloc = false;

		if (maxbuckets < GY_ARRAY_SIZE(tmpcache)) {
			ptmpcache = tmpcache;
		}
		else {
			ptmpcache = new (std::nothrow) HIST_SERIAL[maxbuckets];
			if (!ptmpcache) {
				ptmpcache = cache;	
			}		
			else {
				is_alloc = true;
			}	
		}		

		if (ptmpcache != cache) {
			std::memcpy(ptmpcache, cache, sizeof(cache));
			std::memset(cache, 0, sizeof(cache));
		}	
		
		ret = phistogram->add_histogram_data(tcurrbucket, ptmpcache, maxbuckets);

		if (gy_unlikely(ptmpcache == cache)) {
			std::memset(cache, 0, sizeof(cache));
		}

		if (is_alloc) {
			delete [] ptmpcache;
		}	

		return ret;
	}	

	time_t get_last_rec_time() const noexcept
	{
		return GY_READ_ONCE(tcurrbucket);
	}	
};	

/*
 * Time series Histogram : Histogram with 1 or more Windowed Time data sets (Uses folly::TimeseriesSlabHistogram)
 *
 * Will allocate heap memory initially and requires a mutex lock for every operation : Only supports int64_t data type
 *
 * To instantiate, create a HashClass which will give the bucket id from a data value such as SEMI_LOG_HASH and a 
 * Time LevelClass such as Level_300_all giving the Time Slot Windows for the data needed.
 */ 
template <typename HashClass, typename LevelClass = HashClass, typename ScopeLock = SCOPE_GY_MUTEX>
class TIME_HISTOGRAM
{
public :	
	using 	TimeSeriesHist 		= folly::TimeseriesSlabHistogram<int64_t, HashClass>;
	using 	StatsClock 		= folly::LegacyStatsClock<std::chrono::seconds>;

	static constexpr size_t		ndist_levels = GY_ARRAY_SIZE(LevelClass::dist_seconds);

	TimeSeriesHist			slabhist;

	time_t				inittime;
	const char		* const	stattypestr;
	mutable GY_MUTEX		mutex;
	time_t				last_flush_time;
	time_t				last_add_time;

	static_assert(HashClass::get_max_buckets() < GY_MAX_HISTOGRAM_BUCKETS && HashClass::get_max_buckets() > 1);

	static_assert(ndist_levels < GY_MAX_HISTOGRAM_TIME_LEVELS);

	static_assert(true == noexcept(std::declval<HashClass>()(0)), "Hash Operator () needs to be noexcept");

	TIME_HISTOGRAM(const char *stats_type_string, size_t ntimeseries_buckets = 10) 
		: 
		slabhist(HashClass::max_buckets - 2, HashClass::get_threshold_array(), HashClass::min_value, HashClass::max_value, 
				folly::MultiLevelTimeSeries<int64_t>(ntimeseries_buckets, GY_ARRAY_SIZE(LevelClass::dist_seconds), LevelClass::dist_seconds)),
		inittime(time(nullptr)), stattypestr(stats_type_string), last_flush_time(0), last_add_time(0)
	{ 
		static_assert(ndist_levels < 128);
	}

	~TIME_HISTOGRAM() noexcept	= default;

	TIME_HISTOGRAM(const TIME_HISTOGRAM &other)
		: slabhist(other.slabhist), inittime(other.inittime), 
		stattypestr(other.stattypestr), last_flush_time(other.last_flush_time), last_add_time(other.last_add_time)
	{}		 	
	
	TIME_HISTOGRAM(TIME_HISTOGRAM && other) noexcept
		: slabhist(std::move(other.slabhist)), inittime(other.inittime), 
		stattypestr(other.stattypestr), last_flush_time(other.last_flush_time), last_add_time(other.last_add_time)
	{}		 	

	TIME_HISTOGRAM & operator= (const TIME_HISTOGRAM & other)
	{
		if (this != &other) {
			slabhist 		= other.slabhist;
			inittime		= other.inittime;
			stattypestr		= other.stattypestr;
			last_flush_time		= other.last_flush_time;
			last_add_time		= other.last_add_time;
		}	

		return *this;
	}	

	TIME_HISTOGRAM & operator= (TIME_HISTOGRAM && other) noexcept
	{
		if (this != &other) {
			slabhist 		= std::move(other.slabhist);
			inittime		= other.inittime;
			stattypestr		= other.stattypestr;
			last_flush_time		= other.last_flush_time;
			last_add_time		= other.last_add_time;
		}	

		return *this;
	}	

	HashClass get_hash_class() const noexcept
	{
		return HashClass();
	}	

	LevelClass get_level_class() const noexcept
	{
		return LevelClass();
	}	

	inline StatsClock::time_point mktimepoint(time_t value) const noexcept
	{
		return StatsClock::time_point(StatsClock::duration(value));
	}

	int get_level_data(size_t level, HIST_SERIAL *pcache, size_t nbucketsin, bool ignore_sum = false) const noexcept
	{
		assert(level < ndist_levels);

		if (level >= ndist_levels) {
			return -1;
		}
			
		try {
			size_t 			b, n;
			ScopeLock		lock(&this->mutex);

			/*GY_MT_COLLECT_PROFILE(1000, "copy data to Timeseries Histogram cache");*/

			if (ignore_sum == false) {
				for (b = 0; b < slabhist.buckets_.getNumBuckets() && b < nbucketsin; ++b) {
					const auto& levelobj = slabhist.buckets_.getByIndex(b).getLevel(level);

					pcache[b].sum 	= levelobj.sum();
					pcache[b].count = levelobj.count();
				}
			}
			else {
				for (b = 0; b < slabhist.buckets_.getNumBuckets() && b < nbucketsin; ++b) {
					const auto& levelobj = slabhist.buckets_.getByIndex(b).getLevel(level);

					pcache[b].sum 	= 0;
					pcache[b].count = levelobj.count();
				}
			}

			for (; b < nbucketsin; ++b) {
				pcache[b].sum = 0;
				pcache[b].count = 0;
			}

			return 0;
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception while getting multi bucket data from %s timeseries histogram : %s\n", stattypestr, GY_GET_EXCEPT_STRING););
			return -1;
		);	
	}	

	int add_histogram_data(time_t tnow, HIST_SERIAL *pcache, size_t nbucketsin, bool flush_data = false) noexcept
	{
		assert(pcache);
		assert(nbucketsin == HashClass::max_buckets);

		try {
			size_t 			b, n, count = 0;
			ScopeLock		lock(&this->mutex);

			/*GY_MT_COLLECT_PROFILE(1000, "copy data from Timeseries Histogram cache");*/
		
			for (b = 0; b < slabhist.buckets_.getNumBuckets() && b < nbucketsin; ++b) {
				auto& bucket = slabhist.buckets_.getByIndex(b);
				bucket.addValueAggregated(mktimepoint(tnow), pcache[b].sum,  pcache[b].count);

				count += pcache[b].count;
			}

			if (count == 0) {
				return 0;
			}
				
			slabhist.haveNotSeenValue_ = false;
			slabhist.singleUniqueValue_ = false;

			if (tnow > last_add_time) {
				last_add_time = tnow;
			}

			if (flush_data) {
				return flush_locked(tnow);
			}
				
			return 0;
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception while adding multiple elements to %s timeseries histogram : %s\n", stattypestr, GY_GET_EXCEPT_STRING););
			return -1;
		);	
	}	

	int add_data(int64_t data, time_t tnow, size_t & bucket_index, bool flush_data = false) noexcept
	{
		try {
			ScopeLock		lock(&this->mutex);

			/*GY_MT_COLLECT_PROFILE(10000, "add data to timeseries histogram");*/
		
			bucket_index = slabhist.addValue(mktimepoint(tnow), data);

			last_add_time = tnow;

			if (flush_data) {
				return flush_locked(tnow);
			}

			return 0;
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception while adding element to %s timeseries histogram : %s\n", stattypestr, GY_GET_EXCEPT_STRING););
			return -1;
		);	
	}	

	int add_multi_data(const time_t *__restrict__ ptimearr, const int64_t * __restrict__ pdata_arr, size_t nitems, bool flush_data = false) noexcept
	{
		assert(ptimearr);
		assert(pdata_arr);

		try {
			ScopeLock		lock(&this->mutex);

			/*GY_MT_COLLECT_PROFILE(1000, "add multi data to timeseries histogram");*/
		
			for (size_t i = 0; i < nitems; i++) {
				auto		tlast = ptimearr[i];

				if (tlast > last_add_time) {
					last_add_time = tlast;
				}

				slabhist.addValue(mktimepoint(ptimearr[i]), pdata_arr[i]);
			}	

			if (flush_data) {
				return flush_locked(last_add_time);
			}

			return 0;
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception while adding element to %s timeseries histogram : %s\n", stattypestr, GY_GET_EXCEPT_STRING););
			return -1;
		);	
	}	


	int flush(time_t tnow = time(nullptr)) noexcept
	{
		ScopeLock		lock(&this->mutex);
			
		return flush_locked(tnow);
	}	

	void clear_all_data(void) noexcept
	{
		try {
			ScopeLock		lock(&this->mutex);

			/*GY_MT_COLLECT_PROFILE(1000, "clear timeseries histogram data");*/

			slabhist.clear();

			last_flush_time = 0;
			last_add_time = 0;
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception while clearing %s timeseries histogram : %s\n", stattypestr, GY_GET_EXCEPT_STRING););
		);	
	}	 

	// Call flush() before this
	int get_stats(std::chrono::seconds time_offset, TIME_HIST_VAL  *pstats, size_t nstats, int64_t & tcount, int64_t & tsum, double & mean_val) const noexcept
	{
		try {
			assert(pstats);

			int			level = get_level_from_time_offset<LevelClass>(time_offset);

			if (level == -1) {
				time_t		tnow = time(nullptr);

				return get_stats_for_period(tnow - time_offset.count(), tnow, pstats, nstats, tcount, tsum, mean_val);
			}	

			ScopeLock		lock(&this->mutex);

			GY_MT_COLLECT_PROFILE(1000, "get stats from timeseries histogram");
		
			for (size_t i = 0; i < nstats; ++i) {
				pstats[i].data_value = get_bucket_max_threshold<HashClass>(slabhist.getPercentileBucketIdx(pstats[i].percentile, level));

				if (pstats[i].data_value < 0) pstats[i].data_value = 0;
			}

			tcount = slabhist.count(level);
			tsum = slabhist.sum(level); 

			mean_val = (double)tsum/(tcount != 0 ? tcount : 1);

			return 0;
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception while getting stats for %s timeseries histogram : %s\n", stattypestr, GY_GET_EXCEPT_STRING););
			return -1;
		);	
	}

	int get_stats_with_flush(std::chrono::seconds time_offset, TIME_HIST_VAL *pstats, size_t nstats, int64_t & tcount, int64_t & tsum, double & mean_val, time_t tnow = time(nullptr)) noexcept
	{
		flush(tnow);

		return get_stats(time_offset, pstats, nstats, tcount, tsum, mean_val);
	}	

	
	// Call flush() before this
	int get_stats_for_period(time_t starttime, time_t endtime, TIME_HIST_VAL  *pstats, size_t nstats, int64_t & tcount, int64_t & tsum, double & mean_val) const noexcept
	{
		try {
			assert(pstats);

			auto			start = mktimepoint(starttime), end = mktimepoint(endtime + 1);

			ScopeLock		lock(&this->mutex);

			/*GY_MT_COLLECT_PROFILE(1000, "get stats from timeseries histogram for period");*/
		
			for (size_t i = 0; i < nstats; ++i) {
				pstats[i].data_value = get_bucket_max_threshold<HashClass>(slabhist.getPercentileBucketIdx(pstats[i].percentile, start, end));

				if (pstats[i].data_value < 0) pstats[i].data_value = 0;
			}

			tcount = slabhist.count(start, end);
			tsum = slabhist.sum(start, end); 

			mean_val = (double)tsum/(tcount != 0 ? tcount : 1);

			return 0;
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception while getting stats for period for %s timeseries histogram : %s\n", stattypestr, GY_GET_EXCEPT_STRING););
			return -1;
		);	
	}

	int get_stats_for_period_with_flush(time_t starttime, time_t endtime, TIME_HIST_VAL *pstats, size_t nstats, int64_t & tcount, int64_t & tsum, double & mean_val, time_t tnow = time(nullptr)) noexcept
	{
		flush(tnow);

		return get_stats_for_period(starttime, endtime, pstats, nstats, tcount, tsum, mean_val);
	}	

	// Call flush() before this
	int get_total_records_for_period(time_t starttime, time_t endtime, int64_t  *ptotalcount, int64_t *ptotalsum) const noexcept
	{
		try {
			ScopeLock		lock(&this->mutex);

			/*GY_MT_COLLECT_PROFILE(100'000, "get total records from timeseries histogram for period");*/
		
			if (ptotalcount) {
				*ptotalcount = slabhist.count(mktimepoint(starttime), mktimepoint(endtime));
			}	
			if (ptotalsum) {
				*ptotalsum = slabhist.sum(mktimepoint(starttime), mktimepoint(endtime)); 
			}	

			return 0;
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception while getting total records stats for period for %s timeseries histogram : %s\n", 
				stattypestr, GY_GET_EXCEPT_STRING););
			return -1;
		);	

	}	
	
	// Call flush() before this
	char * base_get_print_str(STR_WR_BUF & ss, double percentile, const char *psuffix) const noexcept
	{
		/*GY_MT_COLLECT_PROFILE(1000, "print timeseries histogram stats");*/

		try {

			const time_t			tdiff_start = (last_add_time > inittime ? last_add_time - inittime + 1 : time(nullptr) - inittime + 1);

			for (size_t l = 0; l < ndist_levels; l++) {

				ScopeLock		lock(&this->mutex);

				ss.appendfmt("\t%s Histogram for %s : \n\t", stattypestr, LevelClass::level_string[l]);
				
				size_t		b = 0;

				for (b = 0; b < slabhist.buckets_.getNumBuckets(); ++b) {
					const auto& levelobj = slabhist.buckets_.getByIndex(b).getLevel(l);
					
					ss.appendfmt(" [ %s <= %ld %s : Count %ld : Sum %ld %s ]",  
						stattypestr, get_bucket_max_threshold<HashClass>(b), psuffix, levelobj.count(), levelobj.sum(), psuffix);
				}

				int64_t			max_pct_data = get_bucket_max_threshold<HashClass>(slabhist.getPercentileBucketIdx(percentile, l));
				int64_t			p25 = get_bucket_max_threshold<HashClass>(slabhist.getPercentileBucketIdx(25, l));
				int64_t			p95 = get_bucket_max_threshold<HashClass>(slabhist.getPercentileBucketIdx(95, l));

				auto 			tcount = slabhist.count(l);
				auto 			tsum = slabhist.sum(l); 

				double 			tavg = (double)tsum/(tcount != 0 ? tcount : 1);

				time_t			sec_dist;
				
				if (LevelClass::dist_seconds[l].count() > 0) {
					sec_dist = (LevelClass::dist_seconds[l].count() < tdiff_start ? LevelClass::dist_seconds[l].count() : tdiff_start);
				}
				else {	
				 	sec_dist = tdiff_start;
				}

				ss.appendfmt("\n\n\tPercentile p%.03lf for %s is <= %ld %s : p25 Percentile is <= %ld %s : p95 Percentile is <= %ld %s : "
						"Total Record count %ld : Avg %s is %.03lf %s : Avg Records/sec is %ld\n\n", 
						percentile, LevelClass::level_string[l], max_pct_data, psuffix, p25, psuffix, p95, psuffix, tcount, stattypestr, tavg, 
						psuffix, tcount/sec_dist);
			}

			return ss.buffer();

		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception while getting stat prints for %s timeseries histogram : %s\n", stattypestr, GY_GET_EXCEPT_STRING););
			return ss.buffer();
		);	
	}

	// Call flush() before this
	char * get_print_str(char *pbuf, int lenbuf, double percentile, const char * metric_suffix = "") const noexcept
	{
		return get_print_str({pbuf, (size_t)lenbuf}, percentile, metric_suffix);
	}

	char * get_print_str(STR_WR_BUF & strbuf, double percentile, const char * metric_suffix = "") const noexcept
	{
		return base_get_print_str(strbuf, percentile, metric_suffix);
	}

	time_t get_last_flush_time(void) const noexcept
	{
		return last_flush_time;
	}

	time_t get_last_add_time(void) const noexcept
	{
		return last_add_time;
	}
		
	time_t get_init_time(void) const noexcept
	{
		return inittime;
	}

private :
	int flush_locked(time_t tnow) noexcept
	{
		try {
			GY_MT_COLLECT_PROFILE(1000, "Flush timeseries histogram data");

			slabhist.update(mktimepoint(tnow - 1));

			last_flush_time = tnow;

			return 0;
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1, ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_BOLD_RED, "Exception while flushing %s timeseries histogram : %s\n", stattypestr, GY_GET_EXCEPT_STRING););
			return -1;
		);	
	}	
};	

/*
 * Time Window Levels of 5 sec, 5 min, 5 days and all data
 */ 
class Level_5s_5min_5days_all
{
public :	
	static constexpr std::chrono::seconds	dist_seconds[] {std::chrono::seconds(5), std::chrono::seconds(300), std::chrono::seconds(5 * 24 * 3600), std::chrono::seconds(0)};
	static constexpr size_t			ntime_levels = GY_ARRAY_SIZE(dist_seconds);
	static constexpr const char *		level_string[ntime_levels] {"Last 5 seconds", "Last 5 minutes", "Last 5 days", "Since Process start"};			
};
	
/*
 * Time Window Levels of 300 sec and all data
 */ 
class Level_300_all
{
public :	
	static constexpr std::chrono::seconds	dist_seconds[] {std::chrono::seconds(300), std::chrono::seconds(0)};
	static constexpr size_t			ntime_levels = GY_ARRAY_SIZE(dist_seconds);
	static constexpr const char *		level_string[ntime_levels] {"Last 5 minutes", "Since Process start"};			
};


#if (__cplusplus >= 201700L)

template <typename T, size_t nbuckets> 
static constexpr std::array<T, nbuckets> gy_create_threshold_array(T tmin, T tmax, T tdiff) noexcept
{
	static_assert(nbuckets > 1);

	std::array<T, nbuckets>		marray = {(T)(tmin + tdiff - 1)};	

	for (size_t i = 1; i < nbuckets - 1; ++i) {
		marray[i] = (T)(tmin + (i + 1) * tdiff - 1);
	}

	marray[nbuckets - 1] = tmax;

	return marray;
};	


template <typename T, T tmin_value, T tmax_value, T fixed_diff_val>
class FIXED_DIFF_HASH
{
public :	
	static_assert((tmax_value > tmin_value + fixed_diff_val) && (fixed_diff_val > (T)0));

	static constexpr size_t				max_buckets = gy_div_round_up((T)(tmax_value - tmin_value + 1), fixed_diff_val) + 2;
	static constexpr std::array<T, max_buckets - 2>	nthresholds = gy_create_threshold_array<T, max_buckets - 2>(tmin_value, tmax_value, fixed_diff_val);
	static constexpr T				min_value = tmin_value, max_value = tmax_value + (T)1;
	static constexpr size_t				mid_slot_num = nthresholds.size()/2;
	static constexpr T				mid_slot_value = nthresholds[mid_slot_num];

	[[gnu::const]] static constexpr size_t get_max_buckets() noexcept
	{
		return max_buckets;
	}	

	static const T* get_threshold_array() noexcept
	{
		return nthresholds.data();
	}	

	[[gnu::pure]] size_t operator()(T data) const noexcept
	{
		return get_bucket_from_data(data);
	}
		
	[[gnu::const]] static constexpr size_t get_bucket_from_data(T data) noexcept 
	{
		if (data < min_value) {
			return 0;
		}
		else if (data >= max_value) {
			return max_buckets - 1;
		}	

		return 1 + (data - min_value)/fixed_diff_val;
	}
};

using PERCENT_HASH = FIXED_DIFF_HASH<int64_t, 0, 100, 10>;

#else 

/*
 * C++14 specific
 */ 

class PERCENT_HASH
{
public :	
	static constexpr int64_t	nthresholds[] {9, 19, 29, 39, 49, 59, 69, 79, 89, 99, 100};
	static constexpr size_t		max_buckets = GY_ARRAY_SIZE(nthresholds) + 2;
	static constexpr int64_t	min_value = 0, max_value = nthresholds[GY_ARRAY_SIZE(nthresholds) - 1] + 1;
	static constexpr size_t		mid_slot_num = GY_ARRAY_SIZE(nthresholds)/2;
	static constexpr int64_t	mid_slot_value = nthresholds[mid_slot_num];

	[[gnu::const]] static constexpr size_t get_max_buckets() noexcept
	{
		return max_buckets;
	}	

	static constexpr const int64_t* get_threshold_array() noexcept
	{
		return &nthresholds[0];
	}	

	[[gnu::pure]] size_t operator()(int data) const noexcept
	{
		return get_bucket_from_data(data);
	}
		
	[[gnu::const]] static constexpr size_t get_bucket_from_data(int data) noexcept 
	{
		if (data < min_value) {
			return 0;
		}
		else if (data >= max_value) {
			return max_buckets - 1;
		}	

		return 1 + (data - min_value)/10;
	}
};

#endif

/*
 * The number of buckets is nbuckets + 2. The Hash function should return buckets numbered from 1 onwards
 */ 
class RESP_TIME_HASH
{
public :	
	static constexpr int64_t	nthresholds[] {1, 10, 30, 60, 100, 150, 200, 300, 450, 700, 1'000, 3'000, 15'000};		// in msec
	static constexpr size_t		max_buckets = GY_ARRAY_SIZE(nthresholds) + 2;
	static constexpr int64_t	min_value = 0, max_value = nthresholds[GY_ARRAY_SIZE(nthresholds) - 1] + 1;
	static constexpr size_t		mid_slot_num = GY_ARRAY_SIZE(nthresholds)/2;
	static constexpr int64_t	mid_slot_value = nthresholds[mid_slot_num];

	[[gnu::const]] static constexpr size_t get_max_buckets() noexcept
	{
		return max_buckets;
	}	

	static constexpr const int64_t * get_threshold_array() noexcept
	{
		return &nthresholds[0];
	}	

	[[gnu::pure]] size_t operator()(int64_t data) const noexcept
	{
		return get_bucket_from_data(data);
	}

	[[gnu::const]] static constexpr size_t get_bucket_from_data(int64_t data) noexcept 
	{
		size_t 		nb = 0;

		if (gy_unlikely((uint64_t)data >= max_value)) {
			if (data < min_value) {
				return 0;
			}
			else if (data >= max_value) {
				return max_buckets - 1;
			}	
		}

		if (gy_unlikely(data >= mid_slot_value)) {
			nb = mid_slot_num;
		}
		else {
			nb = 0;
		}	

		for (; nb < GY_ARRAY_SIZE(nthresholds); nb++) {
			if (data <= nthresholds[nb]) {
				return nb + 1;		
			}	
		}

		return nb + 1;
	}	
};	


class SEMI_LOG_HASH
{
public :	
	static constexpr int64_t	nthresholds[] {1, 10, 100, 500, 1000, 5'000, 25'000, 50'000, 100'000, 300'000, 1'000'000, 5'000'000};
	static constexpr size_t		max_buckets = GY_ARRAY_SIZE(nthresholds) + 2;
	static constexpr int64_t	min_value = 0, max_value = nthresholds[GY_ARRAY_SIZE(nthresholds) - 1] + 1;
	static constexpr size_t		mid_slot_num = GY_ARRAY_SIZE(nthresholds)/2;
	static constexpr int64_t	mid_slot_value = nthresholds[mid_slot_num];

	[[gnu::const]] static constexpr size_t get_max_buckets() noexcept
	{
		return max_buckets;
	}	

	static constexpr const int64_t * get_threshold_array() noexcept
	{
		return &nthresholds[0];
	}	

	[[gnu::pure]] size_t operator()(int data) const noexcept
	{
		return get_bucket_from_data(data);
	}
		
	[[gnu::const]] static constexpr size_t get_bucket_from_data(int data) noexcept 
	{
		size_t 		nb = 0;

		if (data < min_value) {
			return 0;
		}
		else if (data >= max_value) {
			return max_buckets - 1;
		}	

		if (data >= mid_slot_value) {
			nb = mid_slot_num;
		}
		else {
			nb = 0;
		}	

		for (; nb < GY_ARRAY_SIZE(nthresholds); nb++) {
			if (data <= nthresholds[nb]) {
				return nb + 1;		
			}	
		}

		return nb + 1;

	}
};

class SEMI_LOG_HASH_LO
{
public :	
	static constexpr int64_t	nthresholds[] {1, 10, 50, 200, 500, 1000, 3000, 6000, 10'000, 15'000, 25'000, 60'000, 150'000};
	static constexpr size_t		max_buckets = GY_ARRAY_SIZE(nthresholds) + 2;
	static constexpr int64_t	min_value = 0, max_value = nthresholds[GY_ARRAY_SIZE(nthresholds) - 1] + 1;
	static constexpr size_t		mid_slot_num = GY_ARRAY_SIZE(nthresholds)/2;
	static constexpr int64_t	mid_slot_value = nthresholds[mid_slot_num];

	[[gnu::const]] static constexpr size_t get_max_buckets() noexcept
	{
		return max_buckets;
	}	

	static const int64_t * get_threshold_array() noexcept
	{
		return &nthresholds[0];
	}	

	[[gnu::pure]] size_t operator()(int data) const noexcept
	{
		return get_bucket_from_data(data);
	}
		
	[[gnu::const]] static constexpr size_t get_bucket_from_data(int data) noexcept 
	{
		size_t 		nb = 0;

		if (data < min_value) {
			return 0;
		}
		else if (data >= max_value) {
			return max_buckets - 1;
		}	

		if (data >= mid_slot_value) {
			nb = mid_slot_num;
		}
		else {
			nb = 0;
		}	

		for (; nb < GY_ARRAY_SIZE(nthresholds); nb++) {
			if (data <= nthresholds[nb]) {
				return nb + 1;		
			}	
		}

		return nb + 1;

	}
};

class DURATION_HASH
{
public :	
	static constexpr int64_t	nthresholds[] {1, 10, 25, 50, 125, 400, 1000, 3000, 6000, 10'000, 25'000, 40'000, 65'000};
	static constexpr size_t		max_buckets = GY_ARRAY_SIZE(nthresholds) + 2;
	static constexpr int64_t	min_value = 0, max_value = nthresholds[GY_ARRAY_SIZE(nthresholds) - 1] + 1;
	static constexpr size_t		mid_slot_num = GY_ARRAY_SIZE(nthresholds)/2;
	static constexpr int64_t	mid_slot_value = nthresholds[mid_slot_num];

	[[gnu::const]] static constexpr size_t get_max_buckets() noexcept
	{
		return max_buckets;
	}	

	static const int64_t * get_threshold_array() noexcept
	{
		return &nthresholds[0];
	}	

	[[gnu::pure]] size_t operator()(int data) const noexcept
	{
		return get_bucket_from_data(data);
	}
		
	[[gnu::const]] static constexpr size_t get_bucket_from_data(int data) noexcept 
	{
		size_t 		nb = 0;

		if (data < min_value) {
			return 0;
		}
		else if (data >= max_value) {
			return max_buckets - 1;
		}	

		if (data >= mid_slot_value) {
			nb = mid_slot_num;
		}
		else {
			nb = 0;
		}	

		for (; nb < GY_ARRAY_SIZE(nthresholds); nb++) {
			if (data <= nthresholds[nb]) {
				return nb + 1;		
			}	
		}

		return nb + 1;
	}
};


class BENCH_HISTOGRAM : public GY_HISTOGRAM<int, DURATION_HASH>
{
public :	
	using NSEC_HIST = GY_HISTOGRAM<int, DURATION_HASH>;

	using NSEC_HIST::NSEC_HIST;

	char * print_stats(STR_WR_BUF & strbuf, const char * metric_suffix = "nsec") const noexcept
	{
		const float 		arr[] {95.0f, 99.0f, 50.0f, 25.0f};

		return NSEC_HIST::print_stats(strbuf, arr, GY_ARRAY_SIZE(arr), metric_suffix);
	}

	~BENCH_HISTOGRAM() noexcept
	{
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Benchmark Histogram stats : %s\n", this->print_stats(STRING_BUFFER<1024>().get_str_buf()));
	}	
};	

class HASH_10_5000
{
public :	
	static constexpr int64_t	nthresholds[] {10, 25, 50, 75, 100, 150, 300, 500, 800, 1000, 2000, 5000};
	static constexpr size_t		max_buckets = GY_ARRAY_SIZE(nthresholds) + 2;
	static constexpr int64_t	min_value = 0, max_value = nthresholds[GY_ARRAY_SIZE(nthresholds) - 1] + 1;
	static constexpr size_t		mid_slot_num = GY_ARRAY_SIZE(nthresholds)/2;
	static constexpr int64_t	mid_slot_value = nthresholds[mid_slot_num];

	[[gnu::const]] static constexpr size_t get_max_buckets() noexcept
	{
		return max_buckets;
	}	

	static const int64_t * get_threshold_array() noexcept
	{
		return &nthresholds[0];
	}	

	[[gnu::pure]] size_t operator()(int data) const noexcept
	{
		return get_bucket_from_data(data);
	}
		
	[[gnu::const]] static constexpr size_t get_bucket_from_data(int data) noexcept 
	{
		size_t 		nb = 0;

		if (data < min_value) {
			return 0;
		}
		else if (data >= max_value) {
			return max_buckets - 1;
		}	

		if (data >= mid_slot_value) {
			nb = mid_slot_num;
		}
		else {
			nb = 0;
		}	

		for (; nb < GY_ARRAY_SIZE(nthresholds); nb++) {
			if (data <= nthresholds[nb]) {
				return nb + 1;		
			}	
		}

		return nb + 1;
	}
};

class HASH_5_250
{
public :	
	static constexpr int64_t	nthresholds[] {5, 10, 20, 40, 60, 80, 100, 140, 200, 250};
	static constexpr size_t		max_buckets = GY_ARRAY_SIZE(nthresholds) + 2;
	static constexpr int64_t	min_value = 0, max_value = nthresholds[GY_ARRAY_SIZE(nthresholds) - 1] + 1;
	static constexpr size_t		mid_slot_num = GY_ARRAY_SIZE(nthresholds)/2;
	static constexpr int64_t	mid_slot_value = nthresholds[mid_slot_num];

	[[gnu::const]] static constexpr size_t get_max_buckets() noexcept
	{
		return max_buckets;
	}	

	static const int64_t * get_threshold_array() noexcept
	{
		return &nthresholds[0];
	}	

	[[gnu::pure]] size_t operator()(int data) const noexcept
	{
		return get_bucket_from_data(data);
	}
		
	[[gnu::const]] static constexpr size_t get_bucket_from_data(int data) noexcept 
	{
		size_t 		nb = 0;

		if (data < min_value) {
			return 0;
		}
		else if (data >= max_value) {
			return max_buckets - 1;
		}	

		if (data >= mid_slot_value) {
			nb = mid_slot_num;
		}
		else {
			nb = 0;
		}	

		for (; nb < GY_ARRAY_SIZE(nthresholds); nb++) {
			if (data <= nthresholds[nb]) {
				return nb + 1;		
			}	
		}

		return nb + 1;
	}

};

class HASH_1_3000
{
public :	
	static constexpr int64_t	nthresholds[] {1, 5, 10, 25, 50, 75, 100, 150, 300, 500, 1000, 3000};
	static constexpr size_t		max_buckets = GY_ARRAY_SIZE(nthresholds) + 2;
	static constexpr int64_t	min_value = 0, max_value = nthresholds[GY_ARRAY_SIZE(nthresholds) - 1] + 1;
	static constexpr size_t		mid_slot_num = GY_ARRAY_SIZE(nthresholds)/2;
	static constexpr int64_t	mid_slot_value = nthresholds[mid_slot_num];

	[[gnu::const]] static constexpr size_t get_max_buckets() noexcept
	{
		return max_buckets;
	}	

	static const int64_t * get_threshold_array() noexcept
	{
		return &nthresholds[0];
	}	

	[[gnu::pure]] size_t operator()(int data) const noexcept
	{
		return get_bucket_from_data(data);
	}
		
	[[gnu::const]] static constexpr size_t get_bucket_from_data(int data) noexcept 
	{
		size_t 		nb = 0;

		if (data < min_value) {
			return 0;
		}
		else if (data >= max_value) {
			return max_buckets - 1;
		}	

		if (data >= mid_slot_value) {
			nb = mid_slot_num;
		}
		else {
			nb = 0;
		}	

		for (; nb < GY_ARRAY_SIZE(nthresholds); nb++) {
			if (data <= nthresholds[nb]) {
				return nb + 1;		
			}	
		}

		return nb + 1;
	}
};

// Specialization for Response Times
template <typename ScopeLock = SCOPE_GY_MUTEX>
class RESP_TIME_HISTOGRAM : public RESP_TIME_HASH, public Level_5s_5min_5days_all, public TIME_HISTOGRAM <RESP_TIME_HASH, Level_5s_5min_5days_all, ScopeLock>
{
public :	
	using RESP_HIST = TIME_HISTOGRAM <RESP_TIME_HASH, Level_5s_5min_5days_all, ScopeLock>;
			
	RESP_TIME_HISTOGRAM() : RESP_HIST("Response")
	{}

	// Call flush() before this
	char * get_print_str(char *pbuf, int lenbuf, double percentile) const noexcept
	{
		STR_WR_BUF		strbuf(pbuf, (size_t)lenbuf);

		return get_print_str(strbuf, percentile);
	}

	char * get_print_str(STR_WR_BUF & strbuf, double percentile) const noexcept
	{
		return RESP_HIST::base_get_print_str(strbuf, percentile, "msec");
	}
};	

// Specialization for Percentage based data
template <typename LevelClass, typename ScopeLock = SCOPE_GY_MUTEX>
class PERCENT_TIME_HISTOGRAM : public PERCENT_HASH, public LevelClass, public TIME_HISTOGRAM<PERCENT_HASH, LevelClass, ScopeLock>
{
public :	
	using PERCENT_HIST = TIME_HISTOGRAM <PERCENT_HASH, LevelClass, ScopeLock>;

	PERCENT_TIME_HISTOGRAM(const char * stat_type_str) : PERCENT_HIST(stat_type_str)
	{}

	// Call flush() before this
	char * get_print_str(char *pbuf, int lenbuf, double percentile) const noexcept
	{
		STR_WR_BUF		strbuf(pbuf, (size_t)lenbuf);

		return get_print_str(strbuf, percentile);
	}

	char * get_print_str(STR_WR_BUF & strbuf, double percentile) const noexcept
	{
		return PERCENT_HIST::base_get_print_str(strbuf, percentile, "%");
	}
};	

} // namespace gyeeta


