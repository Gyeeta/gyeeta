//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma			once

#if defined(USE_JEMALLOC)
	// JEMalloc provides it's own implementation of
	// malloc_usable_size, and that's what we should be using.
#include 		<jemalloc/jemalloc.h>

#else

#include 		<malloc.h>

#endif

namespace gyeeta {

static size_t gy_malloc_usable_size (void *ptr, size_t min_sz = 0) noexcept
{
	size_t			sz = malloc_usable_size(ptr);
	
	return std::max(sz, min_sz);
}	

} // namespace gyeeta

