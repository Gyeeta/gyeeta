/*
 * Wrapper for std::atomic<T> with extra methods such as copy constructor and relaxed non RMW methods
 * Also wrappers for non-atomic types invoked using atomic class methods.
 */
 
#pragma 		once

#include 		<atomic>

namespace gyeeta {

template <typename T>
class gy_atomic : public std::atomic<T> 
{
public :
	static_assert(std::is_integral<T>::value || std::is_enum<T>::value || std::is_pointer<T>::value, "Integral, enum or pointer data type required.");

	static_assert(sizeof(T) <= 8, "Needs a T with size <= 8");

	gy_atomic() noexcept 
		: std::atomic<T>() 
	{}

	~gy_atomic() noexcept		= default;

	constexpr gy_atomic(T desired) noexcept 
		: std::atomic<T>(desired) 
	{};

	gy_atomic(const gy_atomic & other) noexcept 
		: std::atomic<T>(other.load(std::memory_order_relaxed)) 
	{}

	gy_atomic & operator =(const gy_atomic & other) noexcept 
	{
		if (this != &other) {
			std::atomic<T>::operator =(other.load(std::memory_order_relaxed));
		}		

		return *this;
	}	

	// fetch_add without bus locking... Not a RMW operation. Use only if single updater likely
	T fetch_add_relaxed(T i, std::memory_order unused = std::memory_order_relaxed) noexcept
	{
		T olddata = std::atomic<T>::load(std::memory_order_acquire);
		std::atomic<T>::store(olddata + i, std::memory_order_release);

		return olddata;
	} 
	
	// fetch_sub without bus locking... Not a RMW operation. Use only if single updater likely
	T fetch_sub_relaxed(T i, std::memory_order unused = std::memory_order_relaxed) noexcept
	{
		T olddata = std::atomic<T>::load(std::memory_order_acquire);
		std::atomic<T>::store(olddata - i, std::memory_order_release);

		return olddata;
	} 

	// fetch_add without bus locking... Not a RMW operation. Use only if single updater likely. Provides mem order for load and store
	T fetch_add_relaxed(T i, std::memory_order rdorder, std::memory_order wrorder) noexcept
	{
		T olddata = std::atomic<T>::load(rdorder);
		std::atomic<T>::store(olddata + i, wrorder);

		return olddata;
	} 
	
	// fetch_sub without bus locking... Not a RMW operation. Use only if single updater likely. Provides mem order for load and store
	T fetch_sub_relaxed(T i, std::memory_order rdorder, std::memory_order wrorder) noexcept
	{
		T olddata = std::atomic<T>::load(rdorder);
		std::atomic<T>::store(olddata - i, wrorder);

		return olddata;
	} 

	// Like fetch_sub_relaxed() but will clamp to 0 in case result goes negative : Not a RMW operation. Use only if (signed)T is acceptable
	T fetch_sub_relaxed_0(T subval, std::memory_order unused = std::memory_order_relaxed) noexcept
	{
		T 			olddata = std::atomic<T>::load(std::memory_order_acquire);
		std::make_signed_t<T>	o = decltype(o)(olddata), s = decltype(s)(subval);
		
		if (o - s > 0) {
			std::atomic<T>::store(olddata - subval, std::memory_order_release);
			return olddata;
		}
		else {
			std::atomic<T>::store(0, std::memory_order_release);
			return (T)1;
		}	
	} 

	// Like fetch_sub_relaxed() but will clamp to 0 in case result goes negative : Not a RMW operation. Use only if (signed)T is acceptable
	T fetch_sub_relaxed_0(T subval, std::memory_order rdorder, std::memory_order wrorder) noexcept
	{
		T 			olddata = std::atomic<T>::load(rdorder);
		std::make_signed_t<T>	o = decltype(o)(olddata), s = decltype(s)(subval);
		
		if (o - s > 0) {
			std::atomic<T>::store(olddata - subval, wrorder);
			return olddata;
		}
		else {
			std::atomic<T>::store(0, wrorder);
			return (T)1;
		}	
	} 

	// exchange without bus locking... Not a RMW operation. Use only if single updater likely
	T exchange_relaxed(T desired, std::memory_order unused = std::memory_order_relaxed) noexcept
	{
		T olddata = std::atomic<T>::load(std::memory_order_acquire);
		std::atomic<T>::store(desired, std::memory_order_release);

		return olddata;
	} 

	// cmpxchg without bus locking... Not a RMW operation. Use only if single updater likely
	bool compare_exchange_relaxed(T & expected, T desired, std::memory_order suc_unused = std::memory_order_seq_cst, std::memory_order fail_unused = std::memory_order_seq_cst) noexcept
	{
		T olddata = std::atomic<T>::load(std::memory_order_acquire);

		if (olddata == expected) {
			std::atomic<T>::store(desired, std::memory_order_release);
			return true;
		}
		else {
			expected = olddata;
			return false;
		}
	}
};

/*
 * Non Atomic integral class providing methods corresponding to gy_atomic (as well as std::atomic) for use with Templates 
 * where atomic operations are not needed.
 * NOTE : The class members are not thread-safe.
 */
template <typename T>
class gy_noatomic 
{
	T			data_;
public :
	static_assert(std::is_integral<T>::value || std::is_enum<T>::value, "Integral or enum data type required.");

	static constexpr bool 	is_always_lock_free = true;

	gy_noatomic() noexcept 
		: data_() 
	{}

	gy_noatomic(T i) noexcept 
		: data_(i) 
	{}
	
	gy_noatomic(const gy_noatomic & other) noexcept 		= default;

	gy_noatomic & operator =(const gy_noatomic & other) noexcept 	= default;

	operator T () const noexcept 
	{ 
		return data_; 
	}

	T operator= (const T i) noexcept 
	{ 
		data_ = i; 
		return i;
	}

	void store(T i, std::memory_order m = std::memory_order_seq_cst) noexcept 
	{
		data_ = i;
	} 

	T load(std::memory_order m = std::memory_order_seq_cst) const noexcept
	{
		return data_;
	} 

	T fetch_add(T i, std::memory_order m = std::memory_order_seq_cst)  noexcept
	{
		T olddata = data_;
		data_ += i;
		return olddata;
	} 

	T fetch_add_relaxed(T i, std::memory_order m = std::memory_order_seq_cst)  noexcept
	{
		return fetch_add(i, m);
	}

	T operator++ () noexcept
	{
		return fetch_add(1) + 1;
	}

	T operator++ (int) noexcept
	{
		return fetch_add(1);
	}

	T operator+= (T arg) noexcept
	{
		return fetch_add(arg) + arg;
	}	

	T fetch_sub(T i, std::memory_order m = std::memory_order_seq_cst)  noexcept
	{
		T olddata = data_;
		data_ -= i;
		return olddata;
	} 

	T fetch_sub_relaxed(T i, std::memory_order m = std::memory_order_seq_cst)  noexcept
	{
		return fetch_sub(i, m);
	} 

	T operator-- () noexcept
	{
		return fetch_sub(1) - 1;
	}

	T operator-- (int) noexcept
	{
		return fetch_sub(1);
	}

	T operator-= (T arg) noexcept
	{
		return fetch_sub(arg) - arg;
	}	

	T fetch_and(T arg, std::memory_order order = std::memory_order_seq_cst) noexcept
	{
		T olddata = data_;
		data_ &= arg;
		return olddata;
	}

	T fetch_or(T arg, std::memory_order order = std::memory_order_seq_cst) noexcept
	{
		T olddata = data_;
		data_ |= arg;
		return olddata;
	}

	T fetch_xor(T arg, std::memory_order order = std::memory_order_seq_cst) noexcept
	{
		T olddata = data_;
		data_ ^= arg;
		return olddata;
	}

	T operator&= (T arg) noexcept
	{
		return fetch_and(arg) & arg;
	}
	
	T operator|= (T arg) noexcept
	{
		return fetch_or(arg) | arg;
	}	

	T operator^= (T arg) noexcept
	{
		return fetch_xor(arg) ^ arg;
	}	

	T exchange(T desired, std::memory_order m = std::memory_order_seq_cst)  noexcept
	{
		T olddata = data_;
		data_ = desired;
		return olddata;
	} 

	T exchange_relaxed(T desired, std::memory_order m = std::memory_order_seq_cst)  noexcept
	{
		return exchange(desired, m);
	}	

	bool compare_exchange_strong(T & _expected, T _desired, std::memory_order success = std::memory_order_seq_cst, std::memory_order failure = std::memory_order_seq_cst) noexcept
	{
		if (data_ == _expected) {
			data_ = _desired;
			return true;
		}
		else {
			_expected = data_;
			return false;
		}
	}

	bool compare_exchange_relaxed(T & expected, T desired, std::memory_order success = std::memory_order_seq_cst, std::memory_order failure = std::memory_order_seq_cst) noexcept
	{
		return compare_exchange_strong(expected, desired, success, failure);
	}

	bool compare_exchange_weak(T & expected, T desired, std::memory_order success = std::memory_order_seq_cst, std::memory_order failure = std::memory_order_seq_cst) noexcept
	{	
		return compare_exchange_strong(expected, desired, success, failure);
	}

	bool is_lock_free() const noexcept
	{
		return true;
	}	

};


} // namespace gyeeta
