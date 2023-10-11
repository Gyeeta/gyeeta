//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma			once


#include		"gy_stack_container.h"

#include 		"folly/container/F14Map.h"
#include 		"folly/container/F14Set.h"

namespace gyeeta {

using FollyTransparentStringHash 	= folly::transparent<folly::hasher<folly::StringPiece>>;
using FollyTransparentStringEqual 	= folly::transparent<std::equal_to<folly::StringPiece>>;

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
class INLINE_STACK_F14_MAP : public StackArena<StackSize, alignof(std::max_align_t)>, public folly::F14NodeMap<Key, T, Hash, Keyequal, StackAllocator<std::pair<const Key, T>, StackSize>>
{
public :	
	using Arena		= StackArena<StackSize, alignof(std::max_align_t)>;
	using Allocator		= StackAllocator<std::pair<const Key, T>, StackSize>;
	using Map		= folly::F14NodeMap<Key, T, Hash, Keyequal, StackAllocator<std::pair<const Key, T>, StackSize>>;

	static_assert(StackSize > 2 * (sizeof(Key) + sizeof(T) + 16));

	INLINE_STACK_F14_MAP()
		: Map(Allocator(*(Arena *)this))
	{}

	explicit INLINE_STACK_F14_MAP(size_t bucket_count)
		: Map(bucket_count, Hash(), Keyequal(), Allocator(*(Arena *)this))
	{}	

	INLINE_STACK_F14_MAP(const INLINE_STACK_F14_MAP & other)
		: Map(other,  Allocator(*(Arena *)this))
	{}

	INLINE_STACK_F14_MAP & operator= (const INLINE_STACK_F14_MAP & other)
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
	INLINE_STACK_F14_MAP(INLINE_STACK_F14_MAP && other)	
		: Map(std::move(other),  Allocator(*(Arena *)this))
	{}

	INLINE_STACK_F14_MAP & operator= (INLINE_STACK_F14_MAP && other)
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
class INLINE_STACK_F14_SET : public StackArena<StackSize, alignof(std::max_align_t)>, public folly::F14NodeSet<T, Hash, Keyequal, StackAllocator<T, StackSize>>
{
public :	
	using Arena		= StackArena<StackSize, alignof(std::max_align_t)>;
	using Allocator		= StackAllocator<T, StackSize>;
	using Set		= folly::F14NodeSet<T, Hash, Keyequal, StackAllocator<T, StackSize>>;

	static_assert(StackSize > 2 * (sizeof(T) + 8));

	INLINE_STACK_F14_SET()
		: Set(Allocator(*(Arena *)this))
	{}

	explicit INLINE_STACK_F14_SET(size_t bucket_count)
		: Set(bucket_count, Hash(), Keyequal(), Allocator(*(Arena *)this))
	{}	

	INLINE_STACK_F14_SET(const INLINE_STACK_F14_SET & other)
		: Set(other,  Allocator(*(Arena *)this))
	{}

	INLINE_STACK_F14_SET & operator= (const INLINE_STACK_F14_SET & other)
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
	INLINE_STACK_F14_SET(INLINE_STACK_F14_SET && other)
		: Set(std::move(other),  Allocator(*(Arena *)this))
	{}
		
	INLINE_STACK_F14_SET & operator= (INLINE_STACK_F14_SET && other)
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


} // namespace gyeeta

