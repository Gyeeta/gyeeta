
#pragma			once

#include		"gy_common_inc.h"

#include		<unordered_set>
#include		<unordered_map>
#include		<vector>
#include		<list>

/*
 * Stack Allocated STL containers. Will use heap allocations once allocated stack size exhausted. Not Thread Safe.
 *
 * Deallocations for Stack Arena Memory will not result in memory release unless the deallocated memory is at the end of the arena used.
 * Deallocations for Heap memory will be released though.
 * 
 * To use a container with its own dedicated Stack Arena use the INLINE_STACK_* containers below as shown :
 *
 e.g. using Inline Arena unordered_map : 

 	using Stackmap 		= INLINE_STACK_HASH_MAP<std::string, std::string, 2048>;	// 2048 is the stack space preallocated

	Stackmap		u;

 * To use multiple Containers sharing a single external Arena, use as shown below :
 e.g.
 	using Stackmap 		= GY_STACK_HASH_MAP<std::string, std::string, 4096>;		// 4096 is the stack space of the Arena to be used
	using Arena		= Stackmap::allocator_type::arena_type;

	Arena			arena;
	Stackmap		u(arena), u2(arena);

	u["RED"] 	= "#FF0000";
	u["GREEN"] 	= "#00FF00";
	u2["BLUE"]	= "#0000FF";

 * Once allocated stack size exhausted will use operator new for each subsequent heap allocation.
 *
 * For containers sharing an external arena, the container clear() method will not release memory to the arena and the arena
 * will show memory as already in use. To force the arena to reset, you can call the container::get_allocator()::get_allocator_arena()::reset()
 * or call the reinit_with_arena_reset(container) function.
 *
 * Inline Arena Containers will release memory back to Arena on a clear().
 *
 * XXX Inline Arena Containers have one difference to standard containers. 
 * On container clear(), the container buckets will also be reset as the container is reconstructed.
 * This implies that any buckets or elements reserved will be skipped after clear(). Users should call reserve() after a clear() if needed.
 */

namespace gyeeta {

/*
 * Inspired from http://howardhinnant.github.io/short_alloc.h
 */

template <size_t N, size_t alignment = alignof(std::max_align_t)>
class StackArena
{
	alignas(alignment) char 	buf_[N];
	char				*ptr_;
	uint32_t			nheapallocs_	{0};
	uint32_t			nheapfrees_	{0};

public:
	StackArena() noexcept : ptr_(buf_) 
	{}

	~StackArena() noexcept
	{
		ptr_ = nullptr;
	}

	StackArena(const StackArena&) 			= delete;
	StackArena& operator=(const StackArena&) 	= delete;

	template <size_t ReqAlign = alignof(std::max_align_t)> 
	char * allocate(size_t n);

	void deallocate(char *p, size_t n) noexcept;

	static constexpr size_t size() noexcept 
	{
		return N;
	}

	size_t used() const noexcept 
	{
		return static_cast<size_t>(ptr_ - buf_);
	}
	
	size_t bytes_left() const noexcept 
	{
		return buf_ + N - ptr_;
	}

	void reset() noexcept 
	{
		ptr_ 		= buf_;
		nheapallocs_	= 0;
		nheapfrees_	= 0;
	}

	void * get_curr_ptr() const noexcept
	{
		return ptr_;
	}	

	bool reset_to(char *p) noexcept 
	{
		size_t		ndiffold = p - buf_, ndiff;

		ndiff = align_up(ndiffold);

		p += ndiff - ndiffold;

		if (pointer_in_buffer(p)) {
			ptr_ 		= p;
			nheapallocs_	= 0;
			nheapfrees_	= 0;

			return true;
		}

		return false;
	}

	char * print_stats(STR_WR_BUF & strbuf) const noexcept
	{
		return strbuf.appendfmt("Stack Arena of size %lu : # Bytes Used %lu # Bytes Left %lu # Heap Allocs %u # Heap Frees %u ",
			size(), used(), bytes_left(), nheapallocs_, nheapfrees_);
	}	

private:
	static size_t align_up(size_t n) noexcept
	{
		return (n + (alignment - 1)) & ~(alignment - 1);
	}

	bool pointer_in_buffer(char* p) const noexcept
	{
		return buf_ <= p && p <= buf_ + N;
	}
};

template <size_t N, size_t alignment>
template <size_t ReqAlign>
char * StackArena<N, alignment>::allocate(size_t n)
{
	static_assert(ReqAlign <= alignment, "alignment is too small for this stack arena");

	assert(pointer_in_buffer(ptr_) && "StackArena likely already deallocated");

	auto const aligned_n = align_up(n);

	if (static_cast<decltype(aligned_n)>(buf_ + N - ptr_) >= aligned_n) {
		char	* r = ptr_;
		ptr_ 	+= aligned_n;
		return r;
	}

	nheapallocs_++;

	// Allocate from heap

	if (alignment <= alignof(std::max_align_t)) {
		return static_cast<char *>(::operator new(n));
	}

	return static_cast<char *>(::operator new(n, (std::align_val_t)alignment));
}

template <size_t N, size_t alignment>
void StackArena<N, alignment>::deallocate(char * p, size_t n) noexcept
{
	assert(pointer_in_buffer(ptr_) && "StackArena likely already deallocated");

	if (pointer_in_buffer(p)) {
		n = align_up(n);

		if (p + n == ptr_) {
			ptr_ = p;
		}	
	}
	else {
		nheapfrees_++;
		if (alignment <= alignof(std::max_align_t)) {
			::operator delete(p);
		}
		else {
			::operator delete(p, (std::align_val_t)alignment);
		}
	}	
}

template <class T, size_t N, size_t Align = alignof(std::max_align_t)>
class StackAllocator
{
public:
	using 			value_type = T;
	static auto constexpr 	alignment = Align;
	static auto constexpr 	size = N;

	using 			arena_type = StackArena<size, alignment>;

private:
	arena_type		& a_;

public:
	StackAllocator(const StackAllocator&) = default;

	StackAllocator& operator=(const StackAllocator&) = delete;

	StackAllocator(arena_type & a) noexcept : a_(a)
	{
		static_assert(size % alignment == 0, "size N needs to be a multiple of alignment Align");
	}

	template <class U>
	StackAllocator(const StackAllocator<U, N, alignment>& a) noexcept
		: a_(a.a_) 
	{}

	template <class _Up> 
	struct rebind 
	{
		using other = StackAllocator<_Up, N, alignment>;
	};

	T* allocate(size_t n)
	{
		return reinterpret_cast<T*>(a_.template allocate<alignof(T)>(n * sizeof(T)));
	}

	void deallocate(T* p, size_t n) noexcept
	{
		a_.deallocate(reinterpret_cast<char*>(p), n * sizeof(T));
	}

	arena_type & get_allocator_arena() noexcept
	{
		return a_;
	}	

	template <class T1, size_t N1, size_t A1, class U, size_t M, size_t A2>
	friend bool operator==(const StackAllocator<T1, N1, A1>& x, const StackAllocator<U, M, A2>& y) noexcept;

	template <class U, size_t M, size_t A> friend class StackAllocator;
};

template <class T, size_t N, size_t A1, class U, size_t M, size_t A2>
inline bool operator==(const StackAllocator<T, N, A1>& x, const StackAllocator<U, M, A2>& y) noexcept
{
	return N == M && A1 == A2 && &x.a_ == &y.a_;
}

template <class T, size_t N, size_t A1, class U, size_t M, size_t A2>
inline bool operator!=(const StackAllocator<T, N, A1>& x, const StackAllocator<U, M, A2>& y) noexcept
{
	return !(x == y);
}

/*
 * Stack Containers with external Arena. Single Arena can be shared across multiple containers.
 * Note that on a clear(), the arena will not be reset...
 */
template <
	class 		T, 
	size_t		StackSize = std::min(1024ul, (sizeof(T) + 8) * 64),
	class 		Hash = std::hash<T>,
	class 		Keyequal = std::equal_to<T>
	>
using 	GY_STACK_HASH_SET = std::unordered_set<T, Hash, Keyequal, StackAllocator<T, StackSize>>;


template <
	class 		Key,
	class 		T,
	size_t 		StackSize = std::min(1024ul, (sizeof(std::pair<const Key, T>) + 8) * 64),
	class 		Hash = std::hash<Key>,
	class 		Keyequal = std::equal_to<Key>
	> 
using 	GY_STACK_HASH_MAP = std::unordered_map<Key, T, Hash, Keyequal, StackAllocator<std::pair<const Key, T>, StackSize>>;


template <
	class 		T, 
	size_t 		StackSize = 1024,
	size_t		Alignbytes = alignof(T)
	>
using 	GY_STACK_VECTOR = std::vector<T, StackAllocator<T, StackSize, Alignbytes>>;


template <
	class 		T, 
	size_t 		StackSize = 1024
	>
using 	GY_STACK_LIST = std::list<T, StackAllocator<T, StackSize>>;

/*
 * Destroy and reconstruct the Container and reset Arena. 
 */
template <typename Container>
static void reinit_with_arena_reset(Container & cont, size_t bucket_count = 0)
{
	auto		alloc = cont.get_allocator();
	auto		& arena = alloc.get_allocator_arena();

	cont.~Container();
	arena.reset();

	if (bucket_count == 0) {
		new (&cont) Container(alloc);
	}
	else {
		new (&cont) Container(bucket_count, alloc);
	}	
}	


/*
 * Stack containers with inline Arena. On container clear() the container will be destroyed and constructed again and Arena reset(). 
 * This imples that the bucket count for Map and Set will be 1 initially after a clear()
 */
template <
	class 		Key,
	class 		T,
	size_t 		StackSize = std::min(1024ul, (sizeof(std::pair<const Key, T>) + 8) * 64),
	class 		Hash = std::hash<Key>,
	class 		Keyequal = std::equal_to<Key>
	> 
class INLINE_STACK_HASH_MAP : public StackArena<StackSize, alignof(std::max_align_t)>, public std::unordered_map<Key, T, Hash, Keyequal, StackAllocator<std::pair<const Key, T>, StackSize>>
{
public :	
	using Arena		= StackArena<StackSize, alignof(std::max_align_t)>;
	using Allocator		= StackAllocator<std::pair<const Key, T>, StackSize>;
	using Map		= std::unordered_map<Key, T, Hash, Keyequal, StackAllocator<std::pair<const Key, T>, StackSize>>;

	static_assert(StackSize > 2 * (sizeof(Key) + sizeof(T) + 16));

	INLINE_STACK_HASH_MAP()
		: Map(Allocator(*(Arena *)this))
	{}

	explicit INLINE_STACK_HASH_MAP(size_t bucket_count)
		: Map(bucket_count, Hash(), Keyequal(), Allocator(*(Arena *)this))
	{}	

	INLINE_STACK_HASH_MAP(const INLINE_STACK_HASH_MAP & other)
		: Map(other,  Allocator(*(Arena *)this))
	{}

	INLINE_STACK_HASH_MAP & operator= (const INLINE_STACK_HASH_MAP & other)
	{
		if (this != &other) {
			((Map *)this)->~Map();
			((Arena *)this)->reset();

			Map			*pmap = (Map *)this;	

			new (pmap) Map(other, Allocator(*(Arena *)this));
		}

		return *this;
	}	

	// Not noexcept
	INLINE_STACK_HASH_MAP(INLINE_STACK_HASH_MAP && other)	
		: Map(std::move(other),  Allocator(*(Arena *)this))
	{}

	INLINE_STACK_HASH_MAP & operator= (INLINE_STACK_HASH_MAP && other)
	{
		if (this != &other) {
			((Map *)this)->~Map();
			((Arena *)this)->reset();

			Map			*pmap = (Map *)this;	

			new (pmap) Map(std::move(other), Allocator(*(Arena *)this));
		}

		return *this;
	}	

	using Map::size;

	void clear() noexcept
	{
		try {
			((Map *)this)->~Map();
			((Arena *)this)->reset();

			Map			*pmap = (Map *)this;	

			new (pmap) Map(Allocator(*(Arena *)this));
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINT("Exception caught while re-init of Stack Map : %s : Leaving in dangling state\n", GY_GET_EXCEPT_STRING);
		);
	}	

	const Arena & get_arena() const noexcept
	{
		return *this;
	}	
};

template <
	class 		T, 
	size_t		StackSize = std::min(1024ul, (sizeof(T) + 8) * 64),
	class 		Hash = std::hash<T>,
	class 		Keyequal = std::equal_to<T>
	>
class INLINE_STACK_HASH_SET : public StackArena<StackSize, alignof(std::max_align_t)>, public std::unordered_set<T, Hash, Keyequal, StackAllocator<T, StackSize>>
{
public :	
	using Arena		= StackArena<StackSize, alignof(std::max_align_t)>;
	using Allocator		= StackAllocator<T, StackSize>;
	using Set		= std::unordered_set<T, Hash, Keyequal, StackAllocator<T, StackSize>>;

	static_assert(StackSize > 2 * (sizeof(T) + 8));

	INLINE_STACK_HASH_SET()
		: Set(Allocator(*(Arena *)this))
	{}

	explicit INLINE_STACK_HASH_SET(size_t bucket_count)
		: Set(bucket_count, Hash(), Keyequal(), Allocator(*(Arena *)this))
	{}	

	INLINE_STACK_HASH_SET(const INLINE_STACK_HASH_SET & other)
		: Set(other,  Allocator(*(Arena *)this))
	{}

	INLINE_STACK_HASH_SET & operator= (const INLINE_STACK_HASH_SET & other)
	{
		if (this != &other) {
			((Set *)this)->~Set();
			((Arena *)this)->reset();

			Set			*pset = (Set *)this;	

			new (pset) Set(other, Allocator(*(Arena *)this));
		}

		return *this;
	}	

	// Not noexcept
	INLINE_STACK_HASH_SET(INLINE_STACK_HASH_SET && other)
		: Set(std::move(other),  Allocator(*(Arena *)this))
	{}
		
	INLINE_STACK_HASH_SET & operator= (INLINE_STACK_HASH_SET && other)
	{
		if (this != &other) {
			((Set *)this)->~Set();
			((Arena *)this)->reset();

			Set			*pset = (Set *)this;	

			new (pset) Set(std::move(other), Allocator(*(Arena *)this));
		}

		return *this;
	}	

	using Set::size;

	void clear() noexcept
	{
		try {
			((Set *)this)->~Set();
			((Arena *)this)->reset();

			Set			*pset = (Set *)this;	

			new (pset) Set(Allocator(*(Arena *)this));
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINT("Exception caught while re-init of Stack Set : %s : Leaving in dangling state\n", GY_GET_EXCEPT_STRING);
		);
	}	

	const Arena & get_arena() const noexcept
	{
		return *this;
	}	
};

template <
	class 		T, 
	size_t 		StackSize = 1024,
	size_t		Alignbytes = alignof(T)
	>
class INLINE_STACK_VECTOR : public StackArena<StackSize, Alignbytes>, public std::vector<T, StackAllocator<T, StackSize, Alignbytes>>
{
public :	
	using Arena		= StackArena<StackSize, Alignbytes>;
	using Allocator		= StackAllocator<T, StackSize, Alignbytes>;
	using Vector		= std::vector<T, StackAllocator<T, StackSize, Alignbytes>>;

	static_assert(StackSize > 2 * sizeof(T) + 16);

	INLINE_STACK_VECTOR() noexcept : Vector(Allocator(*(Arena *)this))
	{}

	INLINE_STACK_VECTOR(const INLINE_STACK_VECTOR & other)
		: Vector(other, Allocator(*(Arena *)this))
	{}

	INLINE_STACK_VECTOR(size_t count)
		: Vector(count, Allocator(*(Arena *)this))
	{}

	INLINE_STACK_VECTOR(size_t count, const T & value)
		: Vector(count, value, Allocator(*(Arena *)this))
	{}

	INLINE_STACK_VECTOR & operator= (const INLINE_STACK_VECTOR & other)
	{
		if (this != &other) {
			((Vector *)this)->~Vector();
			((Arena *)this)->reset();

			Vector			*pvec = (Vector *)this;	
			
			new (pvec) Vector(other, Allocator(*(Arena *)this));
		}	

		return *this;
	}	

	// Not noexcept
	INLINE_STACK_VECTOR(INLINE_STACK_VECTOR && other)
		: Vector(std::move(other), Allocator(*(Arena *)this))
	{}

	INLINE_STACK_VECTOR & operator= (INLINE_STACK_VECTOR && other)
	{
		if (this != &other) {
			((Vector *)this)->~Vector();
			((Arena *)this)->reset();

			Vector			*pvec = (Vector *)this;	
			
			new (pvec) Vector(std::move(other), Allocator(*(Arena *)this));
		}	

		return *this;
	}	

	using Vector::size;

	void clear() noexcept
	{
		try {
			((Vector *)this)->~Vector();
			((Arena *)this)->reset();

			Vector			*pvec = (Vector *)this;	
			
			new (pvec) Vector(Allocator(*(Arena *)this));
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINT("Exception caught while re-init of Stack Vector : %s : Leaving in dangling state\n", GY_GET_EXCEPT_STRING);
		);
	}	

	const Arena & get_arena() const noexcept
	{
		return *this;
	}	
};


template <
	class 		T, 
	size_t 		StackSize = 1024,
	size_t		Alignbytes = alignof(T)
	>
class INLINE_STACK_LIST : public StackArena<StackSize, Alignbytes>, public std::list<T, StackAllocator<T, StackSize, Alignbytes>>
{
public :	
	using Arena		= StackArena<StackSize, Alignbytes>;
	using Allocator		= StackAllocator<T, StackSize, Alignbytes>;
	using List		= std::list<T, StackAllocator<T, StackSize, Alignbytes>>;

	static_assert(StackSize > 2 * sizeof(T) + 16);

	INLINE_STACK_LIST() noexcept : List(Allocator(*(Arena *)this))
	{}

	INLINE_STACK_LIST(const INLINE_STACK_LIST & other)
		: List(other, Allocator(*(Arena *)this))
	{}

	INLINE_STACK_LIST(size_t count)
		: List(count, Allocator(*(Arena *)this))
	{}

	INLINE_STACK_LIST(size_t count, const T & value)
		: List(count, value, Allocator(*(Arena *)this))
	{}

	INLINE_STACK_LIST & operator= (const INLINE_STACK_LIST & other)
	{
		if (this != &other) {
			((List *)this)->~List();
			((Arena *)this)->reset();

			List			*plist = (List *)this;	
			
			new (plist) List(other, Allocator(*(Arena *)this));
		}	

		return *this;
	}	

	// Not noexcept
	INLINE_STACK_LIST(INLINE_STACK_LIST && other)
		: List(std::move(other), Allocator(*(Arena *)this))
	{}

	INLINE_STACK_LIST & operator= (INLINE_STACK_LIST && other)
	{
		if (this != &other) {
			((List *)this)->~Vector();
			((Arena *)this)->reset();

			List			*plist = (List *)this;	
			
			new (plist) List(std::move(other), Allocator(*(Arena *)this));
		}	

		return *this;
	}	

	using List::size;

	void clear() noexcept
	{
		try {
			((List *)this)->~List();
			((Arena *)this)->reset();

			List			*plist = (List *)this;	
			
			new (plist) List(Allocator(*(Arena *)this));
		}
		GY_CATCH_EXCEPTION(
			ERRORPRINT("Exception caught while re-init of Stack List : %s : Leaving in dangling state\n", GY_GET_EXCEPT_STRING);
		);
	}	

	const Arena & get_arena() const noexcept
	{
		return *this;
	}	
};


} // namespace gyeeta

